package web

import (
	"context"
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"ntfy-admin/internal/ntfyapi"
	"ntfy-admin/internal/session"
)

const (
	// ntfy session tokens outlive the session slightly, so that the janitor
	// can still revoke them with the token itself after the session expired.
	tokenGrace = 5 * time.Minute

	// maxTokens is ntfy's per-user token limit. Beyond it, ntfy silently
	// deletes the tokens with the lowest expiry, never-expiring ones first.
	maxTokens = 60
)

type loginData struct {
	CSRF     string
	Username string
	Error    string
	Notice   string
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if c, err := r.Cookie(s.cookieName(sessionCookie)); err == nil && s.sessions.Get(c.Value) != nil {
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
	if c, err := r.Cookie(s.cookieName(loginCSRFCookie)); err == nil && len(c.Value) >= 32 {
		return c.Value
	}
	v := session.RandomString(32)
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(loginCSRFCookie), Value: v, Path: s.cookiePath(),
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
	return v
}

// handleLogin authenticates an ntfy admin:
//
//  1. GET /v1/account with Basic auth: checks the password, the admin role
//     and that the account has room for one more token, without creating one.
//  2. POST /v1/account/token, then GET /v1/account with the new token to
//     confirm ntfy issued it for this user (see ntfyapi.ErrWrongUser).
//  3. GET /v1/users with the token, as the final admin check.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	start := time.Now()
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	c, err := r.Cookie(s.cookieName(loginCSRFCookie))
	formCSRF := r.PostForm.Get("csrf")
	if err != nil || formCSRF == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(formCSRF)) != 1 {
		http.Error(w, "invalid or missing CSRF token, reload the login page and try again", http.StatusForbidden)
		return
	}
	ip := s.clientIP(r)
	key := limiterKey(ip)
	username := strings.TrimSpace(r.PostForm.Get("username"))
	password := r.PostForm.Get("password")
	data := loginData{CSRF: formCSRF, Username: username}

	if reason := s.limiter.begin(key); reason != "" {
		s.auditLog(r, username, "login", username, errString("rate limited ("+reason+")"))
		data.Error = "Too many failed login attempts. Try again later."
		if reason == limitGlobal {
			s.log.Warn("global login failure limit reached; logins are paused to keep ntfy from blocking ntfy-admin")
			data.Error = "Too many failed login attempts overall. Logins are paused for a while to keep ntfy from blocking ntfy-admin."
		}
		s.renderStatus(w, r, nil, http.StatusTooManyRequests, "login", "Log in", data)
		return
	}
	failed := false
	defer func() { s.limiter.done(key, failed) }()

	fail := func(msg string, status int) {
		failed = true
		s.auditLog(r, username, "login", username, errString(msg))
		if d := s.cfg.LoginMinDelay - time.Since(start); d > 0 {
			time.Sleep(d)
		}
		data.Error = msg
		s.renderStatus(w, r, nil, status, "login", "Log in", data)
	}
	// ntfyError renders errors that are not a failed authentication; they do
	// not count against the login limit.
	ntfyError := func(step string, err error) {
		s.log.Error("login: "+step+" failed", "user", username, "err", err)
		s.auditLog(r, username, "login", username, err)
		data.Error = describeErr(err)
		status := http.StatusBadGateway
		if ntfyapi.IsTooManyRequests(err) {
			status = http.StatusServiceUnavailable
		}
		s.renderStatus(w, r, nil, status, "login", "Log in", data)
	}
	if !ntfyapi.ValidUsername(username) || password == "" {
		fail("Invalid username or password.", http.StatusUnauthorized)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestDeadline)
	defer cancel()
	basic := ntfyapi.Basic{Username: username, Password: password}
	acc, err := s.ntfy.Account(ctx, basic)
	switch {
	case ntfyapi.IsUnauthorized(err):
		fail("Invalid username or password.", http.StatusUnauthorized)
		return
	case err != nil:
		ntfyError("reading account", err)
		return
	case acc.Username != username:
		// Log in with the exact username (not an e-mail address); anything
		// else could also be a mix-up inside ntfy.
		ntfyError("checking account", errString("ntfy returned a different account; log in with your exact ntfy username."))
		return
	case acc.Role != ntfyapi.RoleAdmin:
		fail("This account is not an ntfy admin.", http.StatusForbidden)
		return
	case len(acc.Tokens) >= maxTokens:
		ntfyError("checking tokens", errString("This admin account already has 60 tokens, ntfy's limit. Logging in would make ntfy delete one of them (never-expiring tokens first). Remove unused tokens in the ntfy web app first."))
		return
	}

	expires := time.Now().Add(s.cfg.SessionTTL)
	tok, err := s.ntfy.CreateVerifiedToken(ctx, basic, username, sessionLabel, expires.Add(tokenGrace).Unix())
	if ntfyapi.IsUnauthorized(err) {
		fail("Invalid username or password.", http.StatusUnauthorized)
		return
	} else if err != nil {
		ntfyError("creating session token", err)
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
		ntfyError("verifying admin rights", err)
		return
	}

	s.limiter.reset(key)
	if old, err := r.Cookie(s.cookieName(sessionCookie)); err == nil {
		s.sessions.Delete(old.Value)
	}
	sess := s.sessions.Create(username, tok.Token, expires)
	http.SetCookie(w, &http.Cookie{
		// A browser-session cookie: expiry is enforced server-side.
		Name: s.cookieName(sessionCookie), Value: sess.ID, Path: s.cookiePath(),
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

const (
	limitIP     = "per-address"
	limitGlobal = "global"
)

// loginLimiter limits failed logins per client address, and globally.
//
// The global limit matters because ntfy itself blocks a client IP after 30
// failed authentications (refilling one per minute), and ntfy sees all of
// ntfy-admin's requests as one IP. Hitting ntfy's limit would block every
// admin session, not only logins, so ntfy-admin stops well below it.
//
// Attempts are counted while in flight, so parallel requests cannot all pass
// the check before the first failure is recorded.
type loginLimiter struct {
	perKey       int
	window       time.Duration
	global       int
	globalWindow time.Duration
	now          func() time.Time

	mu             sync.Mutex
	failures       map[string][]time.Time
	inflight       map[string]int
	globalFailures []time.Time
	globalInflight int
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		perKey: 5, window: 15 * time.Minute,
		// 20 per 30 minutes stays below ntfy's burst of 30, and below its
		// refill rate of one per minute when sustained.
		global: 20, globalWindow: 30 * time.Minute,
		now:      time.Now,
		failures: map[string][]time.Time{},
		inflight: map[string]int{},
	}
}

func prune(ts []time.Time, now time.Time, window time.Duration) []time.Time {
	keep := ts[:0]
	for _, t := range ts {
		if now.Sub(t) < window {
			keep = append(keep, t)
		}
	}
	return keep
}

func (l *loginLimiter) recent(key string, now time.Time) int {
	f := prune(l.failures[key], now, l.window)
	if len(f) == 0 {
		delete(l.failures, key)
	} else {
		l.failures[key] = f
	}
	return len(f)
}

// begin reserves a login attempt. It returns "" if allowed (the caller must
// then call done), or the name of the limit that was hit.
func (l *loginLimiter) begin(key string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.globalFailures = prune(l.globalFailures, now, l.globalWindow)
	if l.recent(key, now)+l.inflight[key] >= l.perKey {
		return limitIP
	}
	if len(l.globalFailures)+l.globalInflight >= l.global {
		return limitGlobal
	}
	l.inflight[key]++
	l.globalInflight++
	return ""
}

// done ends an attempt started with begin.
func (l *loginLimiter) done(key string, failed bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inflight[key]--; l.inflight[key] <= 0 {
		delete(l.inflight, key)
	}
	l.globalInflight--
	if failed {
		now := l.now()
		l.failures[key] = append(l.failures[key], now)
		l.globalFailures = append(l.globalFailures, now)
	}
}

// reset forgets the failures of one key after a successful login. Global
// failures are kept: they still count against ntfy's limit.
func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failures, key)
}

func (l *loginLimiter) sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for key := range l.failures {
		l.recent(key, now)
	}
	l.globalFailures = prune(l.globalFailures, now, l.globalWindow)
}

// limiterKey groups IPv6 clients by /64, since one client usually controls a
// whole /64. IPv4 addresses are used as they are.
func limiterKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
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
		if r.Header.Get("X-Forwarded-For") != "" {
			s.xffWarn.Do(func() {
				s.log.Warn("ignoring X-Forwarded-For from an untrusted peer; behind a reverse proxy, set TRUSTED_PROXIES to its address, or all clients share one login limit and audit IP", "peer", host)
			})
		}
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
