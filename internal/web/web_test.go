package web

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"ntfy-admin/internal/ntfyapi"
	"ntfy-admin/internal/ntfyfake"
)

func setup(t *testing.T, mod func(*Config)) (*ntfyfake.Fake, *testApp) {
	t.Helper()
	f := ntfyfake.New("admin", "adminpw")
	t.Cleanup(f.Close)
	return f, newApp(t, f.URL, mod)
}

func loggedIn(t *testing.T, mod func(*Config)) (*ntfyfake.Fake, *testApp) {
	t.Helper()
	f, a := setup(t, mod)
	r := a.login("admin", "adminpw")
	if r.Path != "/users" || r.Status != 200 {
		t.Fatalf("login failed: %d %s\n%s", r.Status, r.Path, r.Body)
	}
	return f, a
}

func TestLoginLogout(t *testing.T) {
	f, a := setup(t, nil)

	r := a.get("/users")
	if r.Path != "/login" {
		t.Fatalf("unauthenticated access must redirect to login, got %s", r.Path)
	}

	r = a.login("admin", "wrong")
	if r.Status != http.StatusUnauthorized {
		t.Fatalf("bad password: status %d", r.Status)
	}
	a.mustContain(r, "Invalid username or password")

	r = a.login("admin", "adminpw")
	a.mustContain(r, "Everyone (anonymous)", "managed in server.yml / CLI")
	toks := f.Tokens("admin")
	if len(toks) != 1 || toks[0].Label != sessionLabel {
		t.Fatalf("expected one session token, got %+v", toks)
	}
	wantExp := time.Now().Add(12*time.Hour + tokenGrace).Unix()
	if d := toks[0].Expires - wantExp; d < -5 || d > 5 {
		t.Fatalf("session token expiry off by %ds", d)
	}
	a.mustNotContain(r, toks[0].Token)

	r = a.post("/logout", nil)
	if r.Path != "/login" {
		t.Fatalf("logout should land on login, got %s", r.Path)
	}
	if f.TokenCount() != 0 {
		t.Fatal("logout must revoke the ntfy session token")
	}
	if r := a.get("/users"); r.Path != "/login" {
		t.Fatal("session must be gone after logout")
	}
	if !strings.Contains(a.audit.String(), `"action":"logout"`) {
		t.Fatal("logout not audited")
	}
}

func TestLoginNonAdminRejected(t *testing.T) {
	f, a := setup(t, nil)
	f.AddRegularUser("phil", "philpw")
	r := a.login("phil", "philpw")
	if r.Status != http.StatusForbidden {
		t.Fatalf("status %d", r.Status)
	}
	a.mustContain(r, "not an ntfy admin")
	if n := len(f.Tokens("phil")); n != 0 {
		t.Fatalf("token of rejected login must be deleted, %d left", n)
	}
}

func TestLoginRateLimit(t *testing.T) {
	f, a := setup(t, nil)
	for i := 0; i < 5; i++ {
		if r := a.login("admin", "wrong"); r.Status != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, r.Status)
		}
	}
	r := a.login("admin", "adminpw")
	if r.Status != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", r.Status)
	}
	if n := f.CountCalls("POST /v1/account/token"); n != 5 {
		t.Fatalf("blocked logins must not reach ntfy, got %d token calls", n)
	}
}

func TestLoginMinDelay(t *testing.T) {
	_, a := setup(t, func(c *Config) { c.LoginMinDelay = 200 * time.Millisecond })
	start := time.Now()
	a.login("nobody", "x")
	if time.Since(start) < 200*time.Millisecond {
		t.Fatal("failed login answered faster than LoginMinDelay")
	}
}

func TestLoginCSRF(t *testing.T) {
	_, a := setup(t, nil)
	r := a.post("/login", url.Values{"username": {"admin"}, "password": {"adminpw"}, "csrf": {"forged"}})
	if r.Status != http.StatusForbidden {
		t.Fatalf("login without matching CSRF cookie: %d", r.Status)
	}
}

func TestCSRFRequired(t *testing.T) {
	f, a := loggedIn(t, nil)
	r := a.post("/users", url.Values{"username": {"eve"}, "password": {"x"}, "csrf": {"wrong"}})
	if r.Status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", r.Status)
	}
	if f.UserExists("eve") {
		t.Fatal("mutation must not happen without CSRF token")
	}
}

func TestSecurityHeaders(t *testing.T) {
	_, a := setup(t, nil)
	r := a.get("/login")
	for k, want := range map[string]string{
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
	} {
		if got := r.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	csp := r.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
		t.Errorf("weak CSP: %s", csp)
	}
	if strings.Contains(r.Body, "<script>") || strings.Contains(r.Body, "style=") {
		t.Error("templates must not contain inline scripts or styles")
	}
}

func TestSessionCookieFlags(t *testing.T) {
	f := ntfyfake.New("admin", "adminpw")
	defer f.Close()
	a := newApp(t, f.URL, func(c *Config) { c.CookieSecure = true })
	r := a.get("/login")
	csrf := csrfRe.FindStringSubmatch(r.Body)[1]
	form := url.Values{"username": {"admin"}, "password": {"adminpw"}, "csrf": {csrf}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: loginCSRFCookie, Value: csrf})
	rec := httptest.NewRecorder()
	a.srv.Handler().ServeHTTP(rec, req)
	var sc *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			sc = c
		}
	}
	if sc == nil || !sc.HttpOnly || !sc.Secure || sc.SameSite != http.SameSiteStrictMode {
		t.Fatalf("bad session cookie: %+v", sc)
	}
}

func TestUserLifecycle(t *testing.T) {
	f, a := loggedIn(t, nil)

	r := a.post("/users", url.Values{
		"username": {"phil"}, "password": {"pw1"},
		"topic": {"alerts", "", "backup_*"}, "permission": {"read-write", "read-only", "read-only"},
	})
	if r.Path != "/users/phil" {
		t.Fatalf("expected redirect to user page, got %s", r.Path)
	}
	a.mustContain(r, "created with 2 rule(s)", "<code>alerts</code>", "<code>backup_*</code>")
	if g := f.Grants("phil"); len(g) != 2 {
		t.Fatalf("grants: %+v", g)
	}

	r = a.post("/users", url.Values{"username": {"phil"}, "password": {"x"}})
	a.mustContain(r, "already exists")

	a.post("/users/phil/password", url.Values{"password": {"pw2"}})
	if f.Password("phil") != "pw2" {
		t.Fatal("password not changed")
	}

	a.post("/users/phil/access", url.Values{"topic": {"alerts"}, "permission": {"deny-all"}})
	if g := f.Grants("phil"); g[0].Permission != "deny-all" {
		t.Fatalf("grant upsert failed: %+v", g)
	}

	r = a.post("/users/phil/access", url.Values{"topic": {"bad/topic"}, "permission": {"read-only"}})
	a.mustContain(r, "Invalid topic or pattern")

	a.post("/users/phil/access/revoke", url.Values{"topic": {"backup_*"}})
	if g := f.Grants("phil"); len(g) != 1 {
		t.Fatalf("revoke failed: %+v", g)
	}

	r = a.post("/users/phil/access/reset", url.Values{"confirm": {"wrong"}})
	a.mustContain(r, "type the exact username")
	if len(f.Grants("phil")) != 1 {
		t.Fatal("revoke-all must require confirmation")
	}
	a.post("/users/phil/access/reset", url.Values{"confirm": {"phil"}})
	if len(f.Grants("phil")) != 0 {
		t.Fatal("revoke-all failed")
	}

	r = a.post("/users/phil/delete", nil)
	if r.Path != "/users" || f.UserExists("phil") {
		t.Fatalf("delete failed: %s", r.Path)
	}

	audit := a.audit.String()
	for _, action := range []string{"user.add", "access.grant", "user.password", "access.revoke", "access.revoke-all", "user.delete"} {
		if !strings.Contains(audit, `"action":"`+action+`"`) {
			t.Errorf("action %s not audited", action)
		}
	}
	if strings.Contains(audit, "pw1") || strings.Contains(audit, "pw2") || strings.Contains(a.logs.String(), "pw2") {
		t.Error("passwords must never be logged")
	}
}

func TestUserAddValidation(t *testing.T) {
	f, a := loggedIn(t, nil)
	r := a.post("/users", url.Values{"username": {"svc-sneaky"}, "password": {"x"}})
	a.mustContain(r, "reserved for service accounts")
	r = a.post("/users", url.Values{"username": {"bad name"}, "password": {"x"}})
	a.mustContain(r, "Invalid username")
	r = a.post("/users", url.Values{"username": {"ok"}, "password": {"x"}, "topic": {"x"}, "permission": {"rw"}})
	a.mustContain(r, "invalid permission")
	if f.UserExists("svc-sneaky") || f.UserExists("ok") {
		t.Fatal("invalid input must not reach ntfy")
	}
}

func TestAdminIsReadOnly(t *testing.T) {
	f, a := loggedIn(t, nil)
	r := a.get("/users/admin")
	a.mustContain(r, "read-only here")
	a.mustNotContain(r, "/users/admin/delete", "Save rule")

	r = a.post("/users/admin/delete", nil)
	a.mustContain(r, "not a regular user")
	a.post("/users/admin/password", url.Values{"password": {"x"}})
	a.post("/users/admin/access", url.Values{"topic": {"t"}, "permission": {"read-only"}})
	if f.CountCalls("DELETE /v1/users") != 0 || f.CountCalls("PUT /v1/users") != 0 || f.CountCalls("PUT /v1/users/access") != 0 {
		t.Fatal("admin modifications must not be sent to ntfy")
	}
}

func TestAnonymousAndTopics(t *testing.T) {
	f, a := loggedIn(t, nil)
	f.AddRegularUser("phil", "pw")

	a.post("/topics/grant", url.Values{"topic": {"backup_*"}, "username": {"phil"}, "permission": {"write-only"}})
	a.post("/topics/grant", url.Values{"topic": {"backup_nas"}, "username": {"phil"}, "permission": {"read-write"}})
	r := a.post("/topics/public", url.Values{"topic": {"backup_nas"}})
	if g := f.Grants("*"); len(g) != 1 || g[0].Topic != "backup_nas" || g[0].Permission != "read-only" {
		t.Fatalf("make public: %+v", g)
	}
	a.mustContain(r, "public read-only", "Also matched by", `href="#t-backup_`, `id="t-backup_*"`)

	r = a.get("/topics?view=matrix")
	a.mustContain(r, "write-only", "Everyone (anonymous)")

	a.post("/topics/private", url.Values{"topic": {"backup_nas"}})
	if g := f.Grants("*"); len(g) != 0 {
		t.Fatalf("make private: %+v", g)
	}
	a.post("/topics/revoke", url.Values{"topic": {"backup_*"}, "username": {"phil"}})
	if g := f.Grants("phil"); len(g) != 1 || g[0].Topic != "backup_nas" {
		t.Fatalf("revoke from topic view: %+v", g)
	}

	r = a.get("/users/*")
	a.mustContain(r, "Everyone (anonymous)", "apply to everyone")
}

func TestBuildTopics(t *testing.T) {
	s := &Server{cfg: Config{SvcPrefix: "svc-"}}
	rows := s.buildTopics([]ntfyapi.User{
		{Username: "*", Role: "anonymous", Grants: []ntfyapi.Grant{{Topic: "news", Permission: "read-only"}}},
		{Username: "phil", Role: "user", Grants: []ntfyapi.Grant{{Topic: "news", Permission: "read-write"}, {Topic: "n*", Permission: "read-only"}}},
		{Username: "svc-x", Role: "user", Grants: []ntfyapi.Grant{{Topic: "*", Permission: "deny-all"}}},
	})
	if len(rows) != 3 {
		t.Fatalf("rows: %+v", rows)
	}
	var news topicRow
	for _, r := range rows {
		if r.Topic == "news" {
			news = r
		}
	}
	if news.Public != "read-only" || len(news.Entries) != 2 || news.Entries[0].Username != "*" {
		t.Fatalf("news row: %+v", news)
	}
	if strings.Join(news.MatchedBy, ",") != "*,n*" {
		t.Fatalf("matched by: %v", news.MatchedBy)
	}
}

func TestServiceAccountFlow(t *testing.T) {
	f, a := loggedIn(t, func(c *Config) { c.NtfyPublicURL = "https://ntfy.example.com/" })

	r := a.post("/service-accounts", url.Values{
		"name": {"backup"}, "topic": {"backups"}, "permission": {"write-only"},
		"label": {"nas script"}, "expiry": {"never"},
	})
	if r.Path != "/service-accounts/svc-backup" {
		t.Fatalf("expected svc page, got %s\n%s", r.Path, r.Body)
	}
	tok := revealedToken(r.Body)
	if tok == "" {
		t.Fatalf("token not revealed:\n%s", r.Body)
	}
	a.mustContain(r, "https://ntfy.example.com/backups", ntfyapi.MaskToken(tok), "nas script", "Copy publish example")
	a.mustNotContain(r, "Copy subscribe example") // write-only account
	toks := f.Tokens("svc-backup")
	if len(toks) != 1 || toks[0].Token != tok || toks[0].Expires != 0 || toks[0].Label != "nas script" {
		t.Fatalf("ntfy tokens: %+v", toks)
	}
	if g := f.Grants("svc-backup"); len(g) != 1 || g[0].Permission != "write-only" {
		t.Fatalf("grants: %+v", g)
	}
	if strings.Contains(a.audit.String(), tok) || strings.Contains(a.logs.String(), tok) {
		t.Fatal("full token must never be logged")
	}

	// Shown only once; afterwards only masked.
	pw1 := f.Password("svc-backup")
	r = a.get("/service-accounts/svc-backup")
	a.mustNotContain(r, tok)
	a.mustContain(r, ntfyapi.MaskToken(tok))
	if f.Password("svc-backup") == pw1 {
		t.Fatal("listing tokens must rotate the random password")
	}

	// Issue a second token with a custom date.
	date := time.Now().AddDate(0, 1, 0).Format("2006-01-02")
	r = a.post("/service-accounts/svc-backup/tokens", url.Values{"label": {"second"}, "expiry": {"custom"}, "expiry_date": {date}})
	tok2 := revealedToken(r.Body)
	if tok2 == "" || len(f.Tokens("svc-backup")) != 2 {
		t.Fatal("second token not issued")
	}
	if exp := f.Tokens("svc-backup")[1].Expires; time.Unix(exp, 0).UTC().Format("2006-01-02") != date {
		t.Fatalf("custom expiry: %d", exp)
	}

	r = a.post("/service-accounts/svc-backup/tokens", url.Values{"expiry": {"custom"}, "expiry_date": {"2000-01-01"}})
	a.mustContain(r, "must be in the future")

	// Revoke the first token by index (as listed on the page).
	a.get("/service-accounts/svc-backup")
	a.post("/service-accounts/svc-backup/tokens/revoke", url.Values{"idx": {"0"}, "masked": {ntfyapi.MaskToken(tok)}})
	toks = f.Tokens("svc-backup")
	if len(toks) != 1 || toks[0].Token != tok2 {
		t.Fatalf("revoke by index: %+v", toks)
	}
	// A stale form (index 0 now points at tok2) must not revoke the wrong token.
	r = a.post("/service-accounts/svc-backup/tokens/revoke", url.Values{"idx": {"0"}, "masked": {ntfyapi.MaskToken(tok)}})
	a.mustContain(r, "Unknown token")
	if len(f.Tokens("svc-backup")) != 1 {
		t.Fatal("stale revoke must not delete another token")
	}

	// Provisioned tokens cannot be revoked.
	f.AddProvisionedToken("svc-backup", "tk_provisionedprovisionedprovis")
	r = a.get("/service-accounts/svc-backup")
	a.mustContain(r, "from server.yml")

	a.post("/service-accounts/svc-backup/disable", nil)
	if len(f.Grants("svc-backup")) != 0 {
		t.Fatal("disable must revoke all rules")
	}
	r = a.post("/service-accounts/svc-backup/delete", nil)
	if f.UserExists("svc-backup") || r.Path != "/service-accounts" {
		t.Fatal("delete failed")
	}
}

func TestServiceAccountProvisionedTokenRevoke(t *testing.T) {
	f, a := loggedIn(t, nil)
	f.AddRegularUser("svc-p", "pw")
	f.AddProvisionedToken("svc-p", "tk_provisionedprovisionedprovis")
	a.get("/service-accounts/svc-p")
	r := a.post("/service-accounts/svc-p/tokens/revoke", url.Values{"idx": {"0"}, "masked": {ntfyapi.MaskToken("tk_provisionedprovisionedprovis")}})
	a.mustContain(r, "provisioned in server.yml")
	if len(f.Tokens("svc-p")) != 1 {
		t.Fatal("provisioned token must remain")
	}
}

func TestServiceAccountGuards(t *testing.T) {
	f, a := loggedIn(t, nil)
	f.AddRegularUser("phil", "pw")

	// Never PUT /v1/users for missing accounts: ntfy would create them.
	r := a.get("/service-accounts/svc-missing")
	if r.Status != http.StatusNotFound {
		t.Fatalf("status %d", r.Status)
	}
	a.post("/service-accounts/svc-missing/tokens", url.Values{"expiry": {"never"}})
	if f.CountCalls("PUT /v1/users") != 0 || f.UserExists("svc-missing") {
		t.Fatal("must not create missing service accounts via PUT")
	}

	// Never manage tokens of non-prefixed users or admins.
	if r := a.get("/service-accounts/phil"); r.Status != http.StatusNotFound {
		t.Fatalf("non-svc user: %d", r.Status)
	}
	a.post("/service-accounts/admin/tokens", url.Values{"expiry": {"never"}})
	if f.CountCalls("PUT /v1/users") != 0 || f.Password("phil") != "pw" {
		t.Fatal("token management must be limited to service accounts")
	}

	// Duplicate names are refused before touching ntfy.
	f.AddRegularUser("svc-dup", "pw")
	r = a.post("/service-accounts", url.Values{"name": {"svc-dup"}, "expiry": {"never"}})
	a.mustContain(r, "already exists")
	if f.Password("svc-dup") != "pw" {
		t.Fatal("existing user must not be modified")
	}
}

func TestNtfy401EndsSession(t *testing.T) {
	f, a := loggedIn(t, nil)
	f.FailNext("GET", "/v1/users", 401, 40101, "unauthorized")
	r := a.get("/users")
	if r.Path != "/login?expired=1" {
		t.Fatalf("expected re-login, got %s", r.Path)
	}
	a.mustContain(r, "session has expired")
	if a.srv.Sessions().Len() != 0 {
		t.Fatal("session must be removed")
	}
}

func TestNtfy403Surfaced(t *testing.T) {
	f, a := loggedIn(t, nil)
	f.AddRegularUser("phil", "pw")
	f.FailNext("DELETE", "/v1/users", 403, 40301, "forbidden")
	r := a.post("/users/phil/delete", nil)
	a.mustContain(r, "Not permitted by ntfy")
	if !strings.Contains(a.audit.String(), `"result":"error"`) {
		t.Fatal("failed mutation must be audited as error")
	}
}

func TestNtfyDownShowsError(t *testing.T) {
	_, a := loggedIn(t, nil)
	f2 := ntfyfake.New("x", "y")
	f2.Close()
	a.srv.ntfy = ntfyapi.New(f2.URL, nil)
	r := a.get("/users")
	if r.Status != http.StatusBadGateway {
		t.Fatalf("status %d", r.Status)
	}
	a.mustContain(r, "Could not reach ntfy")
}

func TestBasePath(t *testing.T) {
	_, a := setup(t, func(c *Config) { c.BasePath = "/admin/" })
	r := a.login("admin", "adminpw")
	if r.Path != "/admin/users" {
		t.Fatalf("path %s", r.Path)
	}
	a.mustContain(r, `href="/admin/static/style.css"`, `action="/admin/logout"`)
	if r := a.get("/static/app.js"); r.Status != 200 {
		t.Fatalf("static under base path: %d", r.Status)
	}
}

func TestClientIP(t *testing.T) {
	_, ipnet, _ := net.ParseCIDR("10.0.0.0/8")
	s := &Server{cfg: Config{TrustedProxies: []*net.IPNet{ipnet}}}
	req := func(remote string, xff ...string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		for _, x := range xff {
			r.Header.Add("X-Forwarded-For", x)
		}
		return r
	}
	cases := []struct {
		r    *http.Request
		want string
	}{
		{req("1.2.3.4:5", "9.9.9.9"), "1.2.3.4"},                     // untrusted peer: XFF ignored
		{req("10.0.0.1:5", "9.9.9.9"), "9.9.9.9"},                    // trusted proxy
		{req("10.0.0.1:5", "6.6.6.6, 9.9.9.9, 10.0.0.2"), "9.9.9.9"}, // spoofed left entry ignored
		{req("10.0.0.1:5"), "10.0.0.1"},
		{req("10.0.0.1:5", "garbage"), "10.0.0.1"},
	}
	for i, c := range cases {
		if got := s.clientIP(c.r); got != c.want {
			t.Errorf("case %d: got %s, want %s", i, got, c.want)
		}
	}
}

func TestAuditLineShape(t *testing.T) {
	f, a := loggedIn(t, nil)
	f.AddRegularUser("phil", "pw")
	a.post("/users/phil/access", url.Values{"topic": {"t1"}, "permission": {"read-only"}})
	var last map[string]any
	for _, line := range strings.Split(strings.TrimSpace(a.audit.String()), "\n") {
		_ = json.Unmarshal([]byte(line), &last)
	}
	for _, k := range []string{"time", "actor", "ip", "action", "target", "result"} {
		if _, ok := last[k]; !ok {
			t.Errorf("audit line missing %q: %v", k, last)
		}
	}
	if last["actor"] != "admin" || last["action"] != "access.grant" || last["target"] != "phil t1 read-only" || last["result"] != "ok" {
		t.Errorf("audit line: %v", last)
	}
}

func TestHealthz(t *testing.T) {
	_, a := setup(t, nil)
	if r := a.get("/healthz"); r.Status != 200 {
		t.Fatalf("healthz %d", r.Status)
	}
	if r := a.get("/healthz?ntfy=1"); r.Status != 200 {
		t.Fatalf("healthz with ntfy %d", r.Status)
	}
}
