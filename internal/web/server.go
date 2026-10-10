// Package web implements ntfy-admin's HTTP handlers, templates and static assets.
package web

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"ntfy-admin/internal/ntfyapi"
	"ntfy-admin/internal/session"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

const (
	sessionCookie   = "ntfy_admin_session"
	loginCSRFCookie = "ntfy_admin_login_csrf"
	sessionLabel    = "ntfy-admin session"

	// requestDeadline bounds all ntfy calls of one request, below the HTTP
	// server's WriteTimeout, so a slow ntfy yields an error page instead of a
	// dropped connection.
	requestDeadline = 45 * time.Second
)

// Config configures the web server.
type Config struct {
	NtfyURL        string        // internal URL ntfy-admin uses to reach ntfy
	NtfyPublicURL  string        // URL shown in curl examples; defaults to NtfyURL
	BasePath       string        // e.g. "/admin"; "" for root
	CookieSecure   bool          // Secure flag on cookies
	SessionTTL     time.Duration // lifetime of a session and its ntfy token
	SvcPrefix      string        // username prefix that marks service accounts
	TrustedProxies []*net.IPNet  // proxies whose X-Forwarded-For is honoured
	LoginMinDelay  time.Duration // minimum response time for failed logins
}

// Server is the ntfy-admin web application.
type Server struct {
	cfg      Config
	ntfy     *ntfyapi.Client
	sessions *session.Store
	limiter  *loginLimiter
	locks    keyedMutex
	pages    map[string]*template.Template
	xffWarn  sync.Once
	log      *slog.Logger
	audit    *slog.Logger
}

// New creates a server. log receives operational logs, audit receives one
// structured line per mutation.
func New(cfg Config, client *ntfyapi.Client, log, audit *slog.Logger) (*Server, error) {
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 12 * time.Hour
	}
	if cfg.SvcPrefix == "" {
		cfg.SvcPrefix = "svc-"
	}
	if cfg.NtfyPublicURL == "" {
		cfg.NtfyPublicURL = client.BaseURL()
	}
	cfg.NtfyPublicURL = strings.TrimRight(cfg.NtfyPublicURL, "/")
	cfg.BasePath = NormalizeBasePath(cfg.BasePath)
	s := &Server{
		cfg:     cfg,
		ntfy:    client,
		limiter: newLoginLimiter(),
		log:     log,
		audit:   audit,
	}
	s.sessions = session.NewStore(s.revokeSessionToken)
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	return s, nil
}

// Sessions exposes the session store (for the janitor and shutdown).
func (s *Server) Sessions() *session.Store { return s.sessions }

// Limiter exposes the login limiter's sweep (for the janitor).
func (s *Server) SweepLimiter() { s.limiter.sweep() }

// NormalizeBasePath turns "", "/", "admin", "/admin/" into "" or "/admin".
func NormalizeBasePath(p string) string {
	p = strings.Trim(strings.TrimSpace(p), "/")
	if p == "" {
		return ""
	}
	return "/" + p
}

func (s *Server) revokeSessionToken(sess *session.Session) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.ntfy.DeleteToken(ctx, ntfyapi.Bearer(sess.Token), sess.Token)
	if err != nil && !ntfyapi.IsUnauthorized(err) {
		s.log.Warn("revoking session token failed", "user", sess.Username, "token", ntfyapi.MaskToken(sess.Token), "err", err)
		return
	}
	s.log.Info("session ended", "user", sess.Username, "token", ntfyapi.MaskToken(sess.Token))
}

// Handler returns the root HTTP handler, mounted under BasePath.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	static, _ := fs.Sub(staticFS, "static")
	fileServer := http.StripPrefix("/static/", http.FileServer(http.FS(static)))
	mux.Handle("GET /static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		fileServer.ServeHTTP(w, r)
	}))
	mux.HandleFunc("GET /healthz", s.handleHealthz)

	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.Handle("POST /logout", s.authed(s.handleLogout))

	mux.Handle("GET /{$}", s.authed(func(w http.ResponseWriter, r *http.Request, sess *session.Session) {
		s.redirect(w, r, "/users")
	}))
	mux.Handle("GET /users", s.authed(s.handleUsers))
	mux.Handle("POST /users", s.authed(s.handleUserAdd))
	mux.Handle("GET /users/{name}", s.authed(s.handleUser))
	mux.Handle("POST /users/{name}/password", s.authed(s.handleUserPassword))
	mux.Handle("POST /users/{name}/delete", s.authed(s.handleUserDelete))
	mux.Handle("POST /users/{name}/access", s.authed(s.handleUserGrant))
	mux.Handle("POST /users/{name}/access/revoke", s.authed(s.handleUserRevoke))
	mux.Handle("POST /users/{name}/access/reset", s.authed(s.handleUserRevokeAll))

	mux.Handle("GET /topics", s.authed(s.handleTopics))
	mux.Handle("POST /topics/grant", s.authed(s.handleTopicGrant))
	mux.Handle("POST /topics/revoke", s.authed(s.handleTopicRevoke))
	mux.Handle("POST /topics/public", s.authed(s.handleTopicPublic))
	mux.Handle("POST /topics/private", s.authed(s.handleTopicPrivate))

	mux.Handle("GET /service-accounts", s.authed(s.handleSvcList))
	mux.Handle("POST /service-accounts", s.authed(s.handleSvcCreate))
	mux.Handle("GET /service-accounts/{name}", s.authed(s.handleSvc))
	mux.Handle("POST /service-accounts/{name}/tokens", s.authed(s.handleSvcTokenIssue))
	mux.Handle("POST /service-accounts/{name}/tokens/revoke", s.authed(s.handleSvcTokenRevoke))
	mux.Handle("POST /service-accounts/{name}/disable", s.authed(s.handleSvcDisable))
	mux.Handle("POST /service-accounts/{name}/delete", s.authed(s.handleSvcDelete))

	var h http.Handler = mux
	if s.cfg.BasePath != "" {
		inner := http.StripPrefix(s.cfg.BasePath, mux)
		root := http.NewServeMux()
		root.Handle(s.cfg.BasePath+"/", inner)
		root.HandleFunc(s.cfg.BasePath, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, s.cfg.BasePath+"/", http.StatusFound)
		})
		h = root
	}
	return s.securityHeaders(h)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Query().Get("ntfy") == "1" {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if ok, err := s.ntfy.Health(ctx); err != nil || !ok {
			http.Error(w, "ntfy unhealthy", http.StatusServiceUnavailable)
			return
		}
	}
	fmt.Fprintln(w, "ok")
}

type authedHandler func(w http.ResponseWriter, r *http.Request, sess *session.Session)

// authed loads the session, enforces CSRF on POSTs and disables caching.
func (s *Server) authed(h authedHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		var sess *session.Session
		if c, err := r.Cookie(s.cookieName(sessionCookie)); err == nil {
			sess = s.sessions.Get(c.Value)
		}
		if sess == nil {
			if r.Method == http.MethodGet {
				s.redirect(w, r, "/login")
			} else {
				s.redirect(w, r, "/login?expired=1")
			}
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), requestDeadline)
		defer cancel()
		r = r.WithContext(ctx)
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			if !sess.ValidCSRF(r.PostForm.Get("csrf")) {
				s.log.Warn("csrf check failed", "user", sess.Username, "ip", s.clientIP(r), "path", r.URL.Path)
				http.Error(w, "invalid or missing CSRF token, reload the page and try again", http.StatusForbidden)
				return
			}
		}
		h(w, r, sess)
	})
}

// url builds an absolute app path under the base path.
func (s *Server) url(p string) string { return s.cfg.BasePath + p }

func (s *Server) redirect(w http.ResponseWriter, r *http.Request, p string) {
	http.Redirect(w, r, s.url(p), http.StatusSeeOther)
}

// nameSentinel stands in for usernames that cannot be a path segment ("."
// and "..", which ServeMux cleans away); the real name is then passed as the
// "name" query parameter. "~" is not a valid ntfy username.
const nameSentinel = "~"

func entityPath(prefix, name string, suffix []string) string {
	sfx := strings.Join(suffix, "")
	if name == "." || name == ".." {
		return prefix + nameSentinel + sfx + "?name=" + url.QueryEscape(name)
	}
	return prefix + url.PathEscape(name) + sfx
}

// userPath returns /users/{name}[suffix], e.g. userPath("bob", "/delete").
func userPath(name string, suffix ...string) string { return entityPath("/users/", name, suffix) }

// svcPath returns /service-accounts/{name}[suffix].
func svcPath(name string, suffix ...string) string {
	return entityPath("/service-accounts/", name, suffix)
}

// withQuery appends a query parameter to an app path.
func withQuery(p, key, value string) string {
	sep := "?"
	if strings.Contains(p, "?") {
		sep = "&"
	}
	return p + sep + url.QueryEscape(key) + "=" + url.QueryEscape(value)
}

// nameParam returns the {name} path value, resolving nameSentinel.
func nameParam(r *http.Request) string {
	if v := r.PathValue("name"); v != nameSentinel {
		return v
	}
	return r.URL.Query().Get("name")
}

// ntfyFailed handles an error from ntfy for a mutation or page load. It ends
// the session on 401 (token gone or no longer admin) and otherwise flashes
// the error and redirects to back.
func (s *Server) ntfyFailed(w http.ResponseWriter, r *http.Request, sess *session.Session, back string, err error) {
	if ntfyapi.IsUnauthorized(err) {
		s.sessions.Delete(sess.ID)
		s.clearSessionCookie(w)
		s.redirect(w, r, "/login?expired=1")
		return
	}
	if ntfyapi.StatusOf(err) == 0 {
		s.log.Error("ntfy request failed", "path", r.URL.Path, "err", err)
	}
	sess.AddFlash("error", describeErr(err))
	s.redirect(w, r, back)
}

// pageFailed is ntfyFailed for GET pages: redirecting back would loop, so it
// renders an error page instead.
func (s *Server) pageFailed(w http.ResponseWriter, r *http.Request, sess *session.Session, err error) {
	if ntfyapi.IsUnauthorized(err) {
		s.ntfyFailed(w, r, sess, "", err)
		return
	}
	s.log.Error("ntfy request failed", "path", r.URL.Path, "err", err)
	s.renderStatus(w, r, sess, http.StatusBadGateway, "error", "Error", map[string]any{"Message": describeErr(err)})
}

// describeErr turns an error into a message for the UI. Transport errors
// are not shown in detail (they reveal internal addresses); they are logged.
func describeErr(err error) string {
	var es errString
	if errors.As(err, &es) {
		return string(es)
	}
	if errors.Is(err, ntfyapi.ErrWrongUser) {
		return "ntfy answered for a different user than expected; the action was aborted. Please try again."
	}
	var apiErr *ntfyapi.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.Status {
		case http.StatusUnauthorized:
			return "Session expired or not permitted (ntfy: " + apiErr.Message + ")"
		case http.StatusForbidden:
			return "Not permitted by ntfy: " + apiErr.Message
		case http.StatusTooManyRequests:
			return "ntfy is rate-limiting ntfy-admin (" + apiErr.Message + "). All of ntfy-admin's requests come from one address; wait a few minutes and try again."
		}
		return "ntfy error: " + apiErr.Message
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "ntfy did not answer in time. Some changes may have been applied; check the current state."
	}
	return "Could not reach ntfy. See the ntfy-admin logs for details."
}

// provisionedHint explains ntfy's HTTP 500 on user changes: ntfy refuses
// to change or delete users defined in server.yml (auth-users) that way.
func provisionedHint(err error) error {
	if ntfyapi.IsServerError(err) {
		return errString("ntfy refused this change (internal server error). This usually means the user is defined in server.yml (auth-users), which cannot be changed through the API.")
	}
	return err
}

// keyedMutex serializes work per key (a username), so that two requests
// cannot interleave read-check-write sequences on the same user.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*keyedLock
}

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

// lock acquires the lock for key and returns its release function.
func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*keyedLock{}
	}
	l := k.locks[key]
	if l == nil {
		l = &keyedLock{}
		k.locks[key] = l
	}
	l.refs++
	k.mu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		k.mu.Lock()
		if l.refs--; l.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(sessionCookie), Value: "", Path: s.cookiePath(), MaxAge: -1,
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
}

// cookieName adds the __Host- prefix when the browser allows it (Secure
// cookie with path "/"), which keeps sibling subdomains from setting it.
func (s *Server) cookieName(name string) string {
	if s.cfg.CookieSecure && s.cfg.BasePath == "" {
		return "__Host-" + name
	}
	return name
}

func (s *Server) cookiePath() string {
	if s.cfg.BasePath == "" {
		return "/"
	}
	return s.cfg.BasePath + "/"
}

// fetchUsers loads all users fresh from ntfy (state is never cached).
func (s *Server) fetchUsers(ctx context.Context, sess *session.Session) ([]ntfyapi.User, error) {
	return s.ntfy.Users(ctx, ntfyapi.Bearer(sess.Token))
}

func findUser(users []ntfyapi.User, name string) (ntfyapi.User, bool) {
	for _, u := range users {
		if u.Username == name {
			return u, true
		}
	}
	return ntfyapi.User{}, false
}

// lookupUser fetches users and returns the named one.
func (s *Server) lookupUser(ctx context.Context, sess *session.Session, name string) (ntfyapi.User, bool, error) {
	users, err := s.fetchUsers(ctx, sess)
	if err != nil {
		return ntfyapi.User{}, false, err
	}
	u, ok := findUser(users, name)
	return u, ok, nil
}

func (s *Server) isSvc(name string) bool {
	return strings.HasPrefix(name, s.cfg.SvcPrefix) && len(name) > len(s.cfg.SvcPrefix)
}
