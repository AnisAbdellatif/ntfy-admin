package web

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"ntfy-admin/internal/ntfyapi"
	"ntfy-admin/internal/session"
)

// ntfy session tokens outlive the session slightly, so that the janitor can
// still revoke them with the token itself after the session has expired.
const tokenGrace = 5 * time.Minute

type loginData struct {
	CSRF     string
	Username string
	Error    string
	Notice   string
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if c, err := r.Cookie(sessionCookie); err == nil && s.sessions.Get(c.Value) != nil {
		s.redirect(w, r, "/users")
		return
	}
	data := loginData{CSRF: s.loginCSRF(w, r)}
	if r.URL.Query().Get("expired") == "1" {
		data.Notice = "Your session has expired or was revoked. Please log in again."
	}
	s.render(w, r, nil, "login", "Log in", data)
}

// loginCSRF returns the double-submit CSRF value for the login form, setting
// the cookie if needed.
func (s *Server) loginCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(loginCSRFCookie); err == nil && len(c.Value) >= 32 {
		return c.Value
	}
	v := session.RandomString(32)
	http.SetCookie(w, &http.Cookie{
		Name: loginCSRFCookie, Value: v, Path: s.cookiePath(),
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
	return v
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	start := time.Now()
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c, err := r.Cookie(loginCSRFCookie)
	formCSRF := r.PostForm.Get("csrf")
	if err != nil || formCSRF == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(formCSRF)) != 1 {
		http.Error(w, "invalid or missing CSRF token, reload the login page and try again", http.StatusForbidden)
		return
	}
	ip := s.clientIP(r)
	username := strings.TrimSpace(r.PostForm.Get("username"))
	password := r.PostForm.Get("password")
	data := loginData{CSRF: formCSRF, Username: username}

	if s.limiter.blocked(ip) {
		s.auditLog(r, username, "login", username, errString("rate limited"))
		data.Error = "Too many failed login attempts. Try again later."
		s.renderStatus(w, r, nil, http.StatusTooManyRequests, "login", "Log in", data)
		return
	}
	fail := func(msg string, status int) {
		s.limiter.fail(ip)
		s.auditLog(r, username, "login", username, errString(msg))
		if d := s.cfg.LoginMinDelay - time.Since(start); d > 0 {
			time.Sleep(d)
		}
		data.Error = msg
		s.renderStatus(w, r, nil, status, "login", "Log in", data)
	}
	if !ntfyapi.ValidUsername(username) || password == "" {
		fail("Invalid username or password.", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	expires := time.Now().Add(s.cfg.SessionTTL)
	tok, err := s.ntfy.CreateToken(ctx, ntfyapi.Basic{Username: username, Password: password}, sessionLabel, expires.Add(tokenGrace).Unix())
	if err != nil {
		if ntfyapi.IsUnauthorized(err) {
			fail("Invalid username or password.", http.StatusUnauthorized)
			return
		}
		s.log.Error("login: creating ntfy token failed", "user", username, "err", err)
		s.auditLog(r, username, "login", username, err)
		data.Error = describeErr(err)
		s.renderStatus(w, r, nil, http.StatusBadGateway, "login", "Log in", data)
		return
	}
	if _, err := s.ntfy.Users(ctx, ntfyapi.Bearer(tok.Token)); err != nil {
		if delErr := s.ntfy.DeleteToken(ctx, ntfyapi.Bearer(tok.Token), tok.Token); delErr != nil {
			s.log.Warn("login: revoking token of rejected login failed", "user", username, "token", ntfyapi.MaskToken(tok.Token), "err", delErr)
		}
		if ntfyapi.IsUnauthorized(err) || ntfyapi.IsForbidden(err) {
			fail("This account is not an ntfy admin.", http.StatusForbidden)
			return
		}
		s.log.Error("login: verifying admin rights failed", "user", username, "err", err)
		s.auditLog(r, username, "login", username, err)
		data.Error = describeErr(err)
		s.renderStatus(w, r, nil, http.StatusBadGateway, "login", "Log in", data)
		return
	}

	s.limiter.reset(ip)
	if old, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.Delete(old.Value)
	}
	sess := s.sessions.Create(username, tok.Token, expires)
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: sess.ID, Path: s.cookiePath(), Expires: expires,
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
	s.log.Info("session started", "user", username, "token", ntfyapi.MaskToken(tok.Token))
	s.auditLog(r, username, "login", username, nil)
	s.redirect(w, r, "/users")
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	s.sessions.Delete(sess.ID)
	s.clearSessionCookie(w)
	s.auditLog(r, sess.Username, "logout", sess.Username, nil)
	s.redirect(w, r, "/login")
}

// loginLimiter counts failed logins per client IP in a sliding window.
type loginLimiter struct {
	max    int
	window time.Duration

	mu       sync.Mutex
	failures map[string][]time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{max: max, window: window, failures: map[string][]time.Time{}}
}

func (l *loginLimiter) recent(ip string, now time.Time) []time.Time {
	var keep []time.Time
	for _, t := range l.failures[ip] {
		if now.Sub(t) < l.window {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.failures, ip)
	} else {
		l.failures[ip] = keep
	}
	return keep
}

func (l *loginLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(ip, time.Now())) >= l.max
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.failures[ip] = append(l.recent(ip, now), now)
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, ip)
}

func (l *loginLimiter) sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for ip := range l.failures {
		l.recent(ip, now)
	}
}

// clientIP returns the client address. X-Forwarded-For is only honoured when
// the direct peer is a trusted proxy; it is then walked from the right,
// skipping trusted proxies, and the first untrusted address wins.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil || !s.trusted(peer) {
		return host
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		for _, part := range strings.Split(h, ",") {
			if p := strings.TrimSpace(part); p != "" {
				hops = append(hops, p)
			}
		}
	}
	client := host
	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(hops[i])
		if ip == nil {
			break
		}
		client = ip.String()
		if !s.trusted(ip) {
			break
		}
	}
	return client
}

func (s *Server) trusted(ip net.IP) bool {
	for _, n := range s.cfg.TrustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
