package web

// Tests for the findings of the October 2026 audit: each one pins down a
// behaviour of real ntfy v2.29.0 (mirrored in ntfyfake) or a guard that no
// other test covered.

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"ntfy-admin/internal/ntfyapi"
	"ntfy-admin/internal/ntfyfake"
)

// rawPost sends a form with the app's cookies and returns the final status
// and body. Unlike testApp.post it is safe to call from several goroutines.
func (a *testApp) rawPost(path string, form url.Values, header http.Header) (int, string, error) {
	req, _ := http.NewRequest(http.MethodPost, a.ts.URL+a.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// --- login ---

func TestLoginParallelAttemptsAreLimited(t *testing.T) {
	f, a := setup(t, nil)
	a.get("/login")
	csrf := a.csrf
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = a.rawPost("/login", url.Values{"username": {"admin"}, "password": {"wrong"}, "csrf": {csrf}}, nil)
		}()
	}
	wg.Wait()
	if n := f.CountCalls("GET /v1/account"); n > 5 {
		t.Fatalf("parallel attempts bypassed the per-address limit: %d reached ntfy", n)
	}
}

func TestGlobalLoginLimitProtectsNtfy(t *testing.T) {
	_, loopback, _ := net.ParseCIDR("127.0.0.0/8")
	f, a := setup(t, func(c *Config) { c.TrustedProxies = []*net.IPNet{loopback} })
	admin := newApp(t, f.URL, nil)
	if r := admin.login("admin", "adminpw"); r.Path != "/users" {
		t.Fatal("admin login failed")
	}
	// Failed logins from 30 different client addresses: ntfy would block
	// ntfy-admin's IP after 30, so ntfy-admin must stop before that.
	a.get("/login")
	csrf := a.csrf
	before := f.CountCalls("GET /v1/account")
	var lastBody string
	for i := range 30 {
		_, body, err := a.rawPost("/login", url.Values{"username": {"admin"}, "password": {"wrong"}, "csrf": {csrf}},
			http.Header{"X-Forwarded-For": {fmt.Sprintf("203.0.113.%d", i+1)}})
		if err != nil {
			t.Fatal(err)
		}
		lastBody = body
	}
	if n := f.CountCalls("GET /v1/account") - before; n > 20 {
		t.Fatalf("%d failed logins reached ntfy; the global limit must stay below ntfy's 30", n)
	}
	if !strings.Contains(lastBody, "Too many failed login attempts overall") {
		t.Fatalf("expected the global limit message, got:\n%s", lastBody)
	}
	if r := admin.get("/users"); r.Status != http.StatusOK || r.Path != "/users" {
		t.Fatalf("existing admin sessions must keep working: %d %s", r.Status, r.Path)
	}
}

func TestLimiterUnit(t *testing.T) {
	l := newLoginLimiter()
	now := time.Now()
	l.now = func() time.Time { return now }
	for range 5 {
		if l.begin("a") != "" {
			t.Fatal("attempt refused too early")
		}
	}
	if l.begin("a") != limitIP {
		t.Fatal("in-flight attempts must count against the limit")
	}
	for range 5 {
		l.done("a", true)
	}
	if l.begin("a") != limitIP {
		t.Fatal("recorded failures must count")
	}
	now = now.Add(16 * time.Minute)
	if l.begin("a") != "" {
		t.Fatal("failures must expire after the window")
	}
	l.done("a", false)
	l.reset("a")
	l.sweep()
	if len(l.failures) != 0 || len(l.inflight) != 0 {
		t.Fatalf("limiter state not cleaned up: %v %v", l.failures, l.inflight)
	}
}

func TestLimiterKeyGroupsIPv6(t *testing.T) {
	if limiterKey("2001:db8:1:2:aaaa::1") != limiterKey("2001:db8:1:2:bbbb::2") {
		t.Fatal("addresses of one /64 must share a limiter key")
	}
	if limiterKey("2001:db8:1:2::1") == limiterKey("2001:db8:1:3::1") {
		t.Fatal("different /64s must not share a key")
	}
	if limiterKey("192.0.2.1") != "192.0.2.1" {
		t.Fatal("IPv4 keys are the address itself")
	}
}

func TestNtfyRateLimitIsExplained(t *testing.T) {
	f, a := loggedIn(t, nil)
	f.SetAuthBurst(0) // ntfy now answers 429 to every authenticated request
	r := a.get("/users")
	a.mustContain(r, "ntfy is rate-limiting ntfy-admin")
	if a.srv.Sessions().Len() != 1 {
		t.Fatal("a 429 from ntfy must not end the session")
	}
	b := newApp(t, f.URL, nil)
	r = b.login("admin", "adminpw")
	if r.Status != http.StatusServiceUnavailable {
		t.Fatalf("login while ntfy rate-limits: %d", r.Status)
	}
	b.mustContain(r, "ntfy is rate-limiting ntfy-admin")
	if b.srv.limiter.recent(limiterKey("127.0.0.1"), time.Now()) != 0 {
		t.Fatal("ntfy's 429 is not a failed login and must not count against the user")
	}
}

func TestLoginRefusesWhenAdminHas60Tokens(t *testing.T) {
	f, a := setup(t, nil)
	f.AddToken("admin", ntfyapi.Token{Token: "tk_neverneverneverneverneverneve", Label: "phone"}) // never expires
	for i := range 59 {
		f.AddToken("admin", ntfyapi.Token{Token: fmt.Sprintf("tk_%029d", i), Expires: time.Now().Add(time.Hour).Unix()})
	}
	r := a.login("admin", "adminpw")
	a.mustContain(r, "already has 60 tokens")
	if f.CountCalls("POST /v1/account/token") != 0 || len(f.Tokens("admin")) != 60 {
		t.Fatal("login must not create a token that makes ntfy prune one")
	}
}

func TestLoginRejectsMisattributedToken(t *testing.T) {
	f, a := setup(t, nil)
	f.AddRegularUser("bob", "pw")
	f.MisattributeNextToken("bob") // ntfy issues the session token for the wrong user
	r := a.login("admin", "adminpw")
	if r.Path == "/users" || a.srv.Sessions().Len() != 0 {
		t.Fatal("a token issued for another user must not become a session")
	}
	a.mustContain(r, "different user")
	if len(f.Tokens("bob")) != 0 {
		t.Fatal("the misattributed token must be revoked")
	}
}

func TestLoginErrorHidesInternalAddress(t *testing.T) {
	down := ntfyfake.New("x", "y")
	down.Close()
	a := newApp(t, down.URL, nil)
	r := a.login("admin", "adminpw")
	a.mustContain(r, "Could not reach ntfy")
	host := strings.TrimPrefix(down.URL, "http://")
	a.mustNotContain(r, host, "dial tcp")
}

// --- sessions ---

func TestExpiredSessionIsEndedAndRevoked(t *testing.T) {
	f, a := setup(t, func(c *Config) { c.SessionTTL = 50 * time.Millisecond })
	if r := a.login("admin", "adminpw"); r.Path != "/users" {
		t.Fatal("login failed")
	}
	time.Sleep(60 * time.Millisecond)
	if r := a.get("/users"); r.Path != "/login" {
		t.Fatalf("GET with an expired session must go to login, got %s", r.Path)
	}
	waitUntil(t, "session token revoked", func() bool { return f.TokenCount() == 0 })

	a.login("admin", "adminpw")
	time.Sleep(60 * time.Millisecond)
	if r := a.post("/users", url.Values{"username": {"x"}, "password": {"y"}}); r.Path != "/login?expired=1" || f.UserExists("x") {
		t.Fatalf("POST with an expired session must not act: %s", r.Path)
	}
}

func TestJanitorSweepRevokesTokens(t *testing.T) {
	f, a := setup(t, func(c *Config) { c.SessionTTL = 50 * time.Millisecond })
	a.login("admin", "adminpw")
	time.Sleep(60 * time.Millisecond)
	a.srv.Sessions().Sweep()
	if f.TokenCount() != 0 || a.srv.Sessions().Len() != 0 {
		t.Fatal("sweep must end expired sessions and revoke their tokens")
	}
}

func TestBasePathCookieAndRedirect(t *testing.T) {
	f := ntfyfake.New("admin", "adminpw")
	defer f.Close()
	a := newApp(t, f.URL, func(c *Config) { c.BasePath = "/admin" })
	rec := httptest.NewRecorder()
	a.srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/admin/" {
		t.Fatalf("/admin must redirect to /admin/: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	rec = httptest.NewRecorder()
	a.srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/login", nil))
	for _, c := range rec.Result().Cookies() {
		if c.Path != "/admin/" {
			t.Fatalf("cookie %s has path %q, want /admin/", c.Name, c.Path)
		}
	}
	rec = httptest.NewRecorder()
	a.srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/users", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("paths outside the base path must not be served: %d", rec.Code)
	}
}

// --- topics ---

func TestEffectiveAnonymousAccessShown(t *testing.T) {
	f, a := loggedIn(t, nil)
	f.AddRegularUser("phil", "pw")
	a.post("/topics/grant", url.Values{"topic": {"al*"}, "username": {"*"}, "permission": {"read-only"}})
	a.post("/topics/grant", url.Values{"topic": {"alerts"}, "username": {"phil"}, "permission": {"read-write"}})
	a.post("/topics/grant", url.Values{"topic": {"secret"}, "username": {"phil"}, "permission": {"read-write"}})
	r := a.get("/topics")
	alerts := topicSection(t, r.Body, "alerts")
	if !strings.Contains(alerts, `data-anon="read-only">anonymous: read-only via al*`) {
		t.Fatalf("anonymous access through a pattern not shown:\n%s", alerts)
	}
	if !strings.Contains(topicSection(t, r.Body, "secret"), `data-anon="default"`) {
		t.Fatal("topics without anonymous rules must say auth-default-access applies")
	}
}

// --- service accounts ---

func TestSvcGuardsSendNothingToNtfy(t *testing.T) {
	f, a := loggedIn(t, nil)
	f.AddRegularUser("phil", "pw")
	a.post("/users/phil/access", url.Values{"topic": {"t"}, "permission": {"read-only"}})
	a.get("/users")
	before := len(f.Calls)
	for _, target := range []string{"phil", "admin", "*"} {
		a.post("/service-accounts/"+url.PathEscape(target)+"/disable", nil)
		a.post("/service-accounts/"+url.PathEscape(target)+"/delete", nil)
		a.post("/service-accounts/"+url.PathEscape(target)+"/tokens", url.Values{"expiry": {"never"}})
		a.post("/service-accounts/"+url.PathEscape(target)+"/tokens/revoke", url.Values{"idx": {"0"}, "masked": {"tk_…"}})
	}
	for _, c := range f.Calls[before:] {
		if c != "GET /v1/users" {
			t.Fatalf("service-account action on a non-service account reached ntfy: %s", c)
		}
	}
	if len(f.Grants("phil")) != 1 || f.Password("phil") != "pw" {
		t.Fatal("non-service account was modified")
	}
}

func TestPasswordChangeRefusedForSvc(t *testing.T) {
	f, a := loggedIn(t, nil)
	f.AddRegularUser("svc-x", "pw")
	r := a.post("/users/svc-x/password", url.Values{"password": {"known"}})
	a.mustContain(r, "no usable password")
	if f.Password("svc-x") != "pw" {
		t.Fatal("service accounts must not get a known password")
	}
}

func TestSvcConcurrentOperations(t *testing.T) {
	f, a := loggedIn(t, nil)
	a.post("/service-accounts", url.Values{"name": {"bulk"}, "expiry": {"never"}})
	csrf := a.csrf
	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, body, err := a.rawPost("/service-accounts/svc-bulk/tokens", url.Values{"csrf": {csrf}, "expiry": {"30d"}, "label": {fmt.Sprint(i)}}, nil)
			if err != nil || !strings.Contains(body, `id="new-token"`) {
				errs <- fmt.Sprintf("issue %d failed (err %v)", i, err)
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, a.ts.URL+"/service-accounts/svc-bulk", nil)
			resp, err := a.client.Do(req)
			if err != nil {
				errs <- err.Error()
				return
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.Contains(string(b), "rejected the service account credentials") {
				errs <- "view failed: credentials rejected"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if n := len(f.Tokens("svc-bulk")); n != 9 {
		t.Fatalf("expected 9 tokens, got %d", n)
	}
}

func TestSvcRefusesBeyond60Tokens(t *testing.T) {
	f, a := loggedIn(t, nil)
	f.AddRegularUser("svc-full", "pw")
	f.AddToken("svc-full", ntfyapi.Token{Token: "tk_productionproductionproducti", Label: "prod"}) // never expires
	for i := range 59 {
		f.AddToken("svc-full", ntfyapi.Token{Token: fmt.Sprintf("tk_%029d", i), Expires: time.Now().Add(time.Hour).Unix()})
	}
	r := a.get("/service-accounts/svc-full")
	a.mustContain(r, "This account has 60 tokens")
	r = a.post("/service-accounts/svc-full/tokens", url.Values{"expiry": {"30d"}})
	a.mustContain(r, "already has 60 tokens")
	toks := f.Tokens("svc-full")
	if len(toks) != 60 || toks[0].Label != "prod" || f.CountCalls("POST /v1/account/token") != 1 /* admin login */ {
		t.Fatalf("issuing must be refused at 60 tokens: %d tokens, first %q", len(toks), toks[0].Label)
	}
}

func TestFakePrunesNeverExpiringTokensFirst(t *testing.T) {
	// Documents the ntfy behaviour behind TestSvcRefusesBeyond60Tokens.
	f := ntfyfake.New("admin", "adminpw")
	defer f.Close()
	f.AddRegularUser("u", "pw")
	f.AddToken("u", ntfyapi.Token{Token: "tk_neverneverneverneverneverneve"})
	c := ntfyapi.New(f.URL, nil)
	for range 60 {
		if _, err := c.CreateToken(t.Context(), ntfyapi.Basic{Username: "u", Password: "pw"}, "", time.Now().Add(time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	for _, tk := range f.Tokens("u") {
		if tk.Expires == 0 {
			t.Fatal("ntfy prunes never-expiring tokens first; the fake must too")
		}
	}
}

func TestSvcPageCrossSiteDoesNotRotate(t *testing.T) {
	f, a := loggedIn(t, nil)
	f.AddRegularUser("svc-x", "pw")
	req, _ := http.NewRequest(http.MethodGet, a.ts.URL+"/service-accounts/svc-x", nil)
	req.Header.Set("Sec-Fetch-Site", "same-site")
	r := a.do(req)
	a.mustContain(r, "Tokens were not loaded")
	req, _ = http.NewRequest(http.MethodHead, a.ts.URL+"/service-accounts/svc-x", nil)
	a.do(req)
	if f.CountCalls("PUT /v1/users") != 0 || f.Password("svc-x") != "pw" {
		t.Fatal("cross-site GET or HEAD must not rotate the password")
	}
	req, _ = http.NewRequest(http.MethodGet, a.ts.URL+"/service-accounts/svc-x", nil)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	a.do(req)
	if f.CountCalls("PUT /v1/users") != 1 {
		t.Fatal("a same-origin GET loads tokens")
	}
}

func TestSvcCreatePartialFailures(t *testing.T) {
	f, a := loggedIn(t, nil)

	f.FailNext("PUT", "/v1/users/access", 500, 50001, "internal server error")
	r := a.post("/service-accounts", url.Values{"name": {"a"}, "topic": {"t"}, "permission": {"read-write"}, "expiry": {"never"}})
	a.mustContain(r, "not all rules were applied and no token was issued")
	if len(f.Tokens("svc-a")) != 0 {
		t.Fatal("no token must be issued after a failed rule")
	}

	f.FailNext("POST", "/v1/account/token", 401, 40101, "unauthorized")
	r = a.post("/service-accounts", url.Values{"name": {"b"}, "expiry": {"never"}})
	a.mustContain(r, "issuing the token failed", "rejected the service account credentials")
	if a.srv.Sessions().Len() != 1 {
		t.Fatal("a 401 for the service account must not end the admin's session")
	}

	f.MisattributeNextToken("admin")
	r = a.post("/service-accounts", url.Values{"name": {"c"}, "expiry": {"never"}})
	a.mustContain(r, "different user")
	if revealedToken(r.Body) != "" || len(f.Tokens("admin")) != 1 /* the session token */ {
		t.Fatal("a token issued for another user must never be shown or kept")
	}
}

func TestProvisionedUsersExplained(t *testing.T) {
	f, a := loggedIn(t, nil)
	f.AddProvisionedUser("bob", "pw")
	f.AddProvisionedUser("svc-prov", "pw")
	r := a.post("/users/bob/password", url.Values{"password": {"new"}})
	a.mustContain(r, "defined in server.yml")
	r = a.post("/users/bob/delete", nil)
	a.mustContain(r, "defined in server.yml")
	r = a.get("/service-accounts/svc-prov")
	a.mustContain(r, "defined in server.yml")
}

func TestRevokeVanishedToken(t *testing.T) {
	f, a := loggedIn(t, nil)
	r := a.post("/service-accounts", url.Values{"name": {"v"}, "expiry": {"never"}})
	tok := revealedToken(r.Body)
	a.get("/service-accounts/svc-v")
	// Revoked elsewhere (another tab, the ntfy web app) after the list was shown.
	if err := ntfyapi.New(f.URL, nil).DeleteToken(t.Context(), ntfyapi.Bearer(tok), tok); err != nil {
		t.Fatal(err)
	}
	r = a.post("/service-accounts/svc-v/tokens/revoke", url.Values{"idx": {"0"}, "masked": {ntfyapi.MaskToken(tok)}})
	a.mustContain(r, "no longer exists")
	if a.srv.Sessions().Len() != 1 {
		t.Fatal("session must survive")
	}
}

func TestDotUsernames(t *testing.T) {
	f, a := loggedIn(t, nil)
	f.AddRegularUser(".", "pw")
	f.AddRegularUser("..", "pw")
	r := a.get("/users")
	a.mustContain(r, `href="/users/~?name=."`, `href="/users/~?name=.."`)
	r = a.get("/users/~?name=..")
	a.mustContain(r, "<h1>.. ")
	a.post("/users/~/access?name=..", url.Values{"topic": {"t"}, "permission": {"read-only"}})
	if len(f.Grants("..")) != 1 {
		t.Fatal("rule for user .. not applied")
	}
	a.post("/users/~/delete?name=.", nil)
	if f.UserExists(".") || !f.UserExists("..") {
		t.Fatal("deleting user . failed or hit the wrong user")
	}
}

func TestNoFullTokenInLogs(t *testing.T) {
	f, a := loggedIn(t, nil)
	r := a.post("/service-accounts", url.Values{"name": {"logs"}, "expiry": {"never"}})
	t1 := revealedToken(r.Body)
	r = a.post("/service-accounts/svc-logs/tokens", url.Values{"expiry": {"30d"}})
	t2 := revealedToken(r.Body)
	r = a.get("/service-accounts/svc-logs")
	a.post("/service-accounts/svc-logs/tokens/revoke", url.Values{"idx": {tokenIndex(t, r.Body, t1)}, "masked": {ntfyapi.MaskToken(t1)}})
	tokens := []string{t1, t2}
	for _, tk := range f.Tokens("admin") {
		tokens = append(tokens, tk.Token) // the session token
	}
	a.post("/logout", nil)
	logs := a.audit.String() + a.logs.String()
	for _, tk := range tokens {
		if tk == "" || strings.Contains(logs, tk) {
			t.Fatalf("full token %q found in logs (or token missing)", ntfyapi.MaskToken(tk))
		}
	}
	for _, action := range []string{"svc.create", "svc.token.issue", "svc.rotate-password", "svc.token.revoke", "logout"} {
		if !strings.Contains(a.audit.String(), `"action":"`+action+`"`) {
			t.Errorf("action %s not audited", action)
		}
	}
}

func TestAnonymousCannotBeDeletedOrRenamed(t *testing.T) {
	f, a := loggedIn(t, nil)
	a.post("/users/%2A/delete", nil)
	a.post("/users/%2A/password", url.Values{"password": {"x"}})
	if f.CountCalls("DELETE /v1/users") != 0 || f.CountCalls("PUT /v1/users") != 0 || !f.UserExists("*") {
		t.Fatal("the anonymous user must not be deleted or given a password")
	}
}

func TestSuccessfulLoginResetsAddressLimit(t *testing.T) {
	_, a := setup(t, nil)
	for range 4 {
		a.login("admin", "wrong")
	}
	if r := a.login("admin", "adminpw"); r.Path != "/users" {
		t.Fatal("login failed")
	}
	a.post("/logout", nil)
	for i := range 4 {
		if r := a.login("admin", "wrong"); r.Status != http.StatusUnauthorized {
			t.Fatalf("attempt %d after a successful login was limited: %d", i, r.Status)
		}
	}
}

func TestReloginReplacesSession(t *testing.T) {
	f, a := loggedIn(t, nil)
	a.login("admin", "adminpw")
	if a.srv.Sessions().Len() != 1 || len(f.Tokens("admin")) != 1 {
		t.Fatalf("logging in again must end the old session: %d sessions, %d tokens", a.srv.Sessions().Len(), len(f.Tokens("admin")))
	}
}

func TestCSPForbidsFraming(t *testing.T) {
	_, a := setup(t, nil)
	if csp := a.get("/login").Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP must forbid framing: %s", csp)
	}
}

func TestSvcNameMustNotBeBarePrefix(t *testing.T) {
	f, a := loggedIn(t, nil)
	r := a.post("/service-accounts", url.Values{"name": {""}, "expiry": {"never"}})
	a.mustContain(r, "Invalid name")
	if f.UserExists("svc-") {
		t.Fatal("an account named exactly like the prefix must not be created")
	}
}
