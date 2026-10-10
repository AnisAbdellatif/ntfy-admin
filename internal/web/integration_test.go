//go:build integration

// Integration test against a real, pinned ntfy (see integration/docker-compose.yml).
// It guards ntfy-admin against changes in ntfy's undocumented admin API.
//
//	make integration
//
// or manually:
//
//	docker compose -f integration/docker-compose.yml up -d --wait
//	NTFY_URL=http://localhost:18080 go test -tags integration ./internal/web/ -run Integration -v
package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"ntfy-admin/internal/ntfyapi"
)

func integrationEnv(t *testing.T) (ntfyURL string, admin ntfyapi.Basic) {
	ntfyURL = os.Getenv("NTFY_URL")
	if ntfyURL == "" {
		ntfyURL = "http://localhost:18080"
	}
	admin = ntfyapi.Basic{Username: envDefault("NTFY_ADMIN_USER", "admin"), Password: envDefault("NTFY_ADMIN_PASSWORD", "adminpass")}
	if ok, err := ntfyapi.New(ntfyURL, nil).Health(context.Background()); err != nil || !ok {
		t.Fatalf("ntfy at %s not healthy (start it with `docker compose -f integration/docker-compose.yml up -d --wait`): %v", ntfyURL, err)
	}
	return ntfyURL, admin
}

func envDefault(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ntfyRequest publishes (body != "") or polls a topic with a bearer token and returns the status.
func ntfyRequest(t *testing.T, ntfyURL, token, topic, body string) int {
	t.Helper()
	var req *http.Request
	if body != "" {
		req, _ = http.NewRequest(http.MethodPost, ntfyURL+"/"+topic, strings.NewReader(body))
	} else {
		req, _ = http.NewRequest(http.MethodGet, ntfyURL+"/"+topic+"/json?poll=1", nil)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestIntegration(t *testing.T) {
	ntfyURL, admin := integrationEnv(t)
	ctx := context.Background()
	api := ntfyapi.New(ntfyURL, nil)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano()%1_000_000_000)
	user := "it-user-" + suffix
	svc := "svc-it-" + suffix
	topic := "it_topic_" + suffix

	a := newApp(t, ntfyURL, nil)
	t.Cleanup(func() {
		// Leave nothing behind if a step fails halfway.
		for _, name := range []string{user, user + "-na", svc} {
			_ = api.DeleteUser(ctx, admin, name)
		}
		_ = api.Revoke(ctx, admin, ntfyapi.Everyone, topic)
	})

	countSessionTokens := func() int {
		acc, err := api.Account(ctx, admin)
		if err != nil {
			t.Fatalf("account: %v", err)
		}
		n := 0
		for _, tk := range acc.Tokens {
			if tk.Label == sessionLabel {
				n++
			}
		}
		return n
	}
	before := countSessionTokens()

	t.Run("login", func(t *testing.T) {
		if r := a.login(admin.Username, "wrong-password"); r.Status != http.StatusUnauthorized {
			t.Fatalf("wrong password: %d", r.Status)
		}
		r := a.login(admin.Username, admin.Password)
		if r.Path != "/users" {
			t.Fatalf("login failed: %d %s\n%s", r.Status, r.Path, r.Body)
		}
		a.mustContain(r, "Everyone (anonymous)")
		if countSessionTokens() != before+1 {
			t.Fatal("login must create exactly one session token")
		}
	})

	t.Run("non-admin login rejected", func(t *testing.T) {
		if err := api.AddUser(ctx, admin, user+"-na", "pw-na"); err != nil {
			t.Fatal(err)
		}
		defer api.DeleteUser(ctx, admin, user+"-na")
		b := newApp(t, ntfyURL, nil)
		if r := b.login(user+"-na", "pw-na"); r.Status != http.StatusForbidden {
			t.Fatalf("non-admin login: %d", r.Status)
		}
		acc, err := api.Account(ctx, ntfyapi.Basic{Username: user + "-na", Password: "pw-na"})
		if err != nil || len(acc.Tokens) != 0 {
			t.Fatalf("rejected login must not leave tokens: %v %+v", err, acc)
		}
	})

	t.Run("users and access", func(t *testing.T) {
		r := a.post("/users", url.Values{"username": {user}, "password": {"pw1"}, "topic": {topic}, "permission": {"read-write"}})
		a.mustContain(r, "created with 1 rule(s)")
		a.post("/users/"+user+"/access", url.Values{"topic": {topic + "_*"}, "permission": {"read-only"}})
		a.post("/topics/public", url.Values{"topic": {topic}})

		users, err := api.Users(ctx, admin)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := findUser(users, user)
		anon, _ := findUser(users, ntfyapi.Everyone)
		if len(u.Grants) != 2 {
			t.Fatalf("user grants: %+v", u.Grants)
		}
		if !hasGrant(anon.Grants, topic, ntfyapi.PermReadOnly) {
			t.Fatalf("anonymous grant missing: %+v", anon.Grants)
		}
		if st := ntfyRequest(t, ntfyURL, "", topic, ""); st != http.StatusOK {
			t.Fatalf("anonymous read of public topic: %d", st)
		}

		r = a.get("/topics")
		if !strings.Contains(topicSection(t, r.Body, topic), `data-anon="read-only"`) {
			t.Fatal("topic not shown as public read-only")
		}

		a.post("/topics/private", url.Values{"topic": {topic}})
		if st := ntfyRequest(t, ntfyURL, "", topic, ""); st == http.StatusOK {
			t.Fatal("anonymous read must be denied after make private")
		}
		users, _ = api.Users(ctx, admin)
		anon, _ = findUser(users, ntfyapi.Everyone)
		if !hasGrant(anon.Grants, topic, ntfyapi.PermDenyAll) {
			t.Fatalf("make private must leave an explicit deny-all rule: %+v", anon.Grants)
		}

		a.post("/users/"+user+"/password", url.Values{"password": {"pw2"}})
		if _, err := api.Account(ctx, ntfyapi.Basic{Username: user, Password: "pw2"}); err != nil {
			t.Fatalf("password change: %v", err)
		}
		a.post("/users/"+user+"/access/reset", url.Values{"confirm": {user}})
		users, _ = api.Users(ctx, admin)
		if u, _ := findUser(users, user); len(u.Grants) != 0 {
			t.Fatalf("revoke all: %+v", u.Grants)
		}
		a.post("/users/"+user+"/delete", nil)
		users, _ = api.Users(ctx, admin)
		if _, ok := findUser(users, user); ok {
			t.Fatal("user not deleted")
		}
	})

	t.Run("service account tokens", func(t *testing.T) {
		r := a.post("/service-accounts", url.Values{
			"name": {svc}, "topic": {topic}, "permission": {"read-write"},
			"label": {"integration"}, "expiry": {"never"},
		})
		tok1 := revealedToken(r.Body)
		if tok1 == "" {
			t.Fatalf("no token revealed: %s\n%s", r.Path, r.Body)
		}
		if st := ntfyRequest(t, ntfyURL, tok1, topic, "hello from integration test"); st != http.StatusOK {
			t.Fatalf("publish with token: %d", st)
		}

		r = a.get("/service-accounts/" + svc)
		a.mustContain(r, "<td><code>"+ntfyapi.MaskToken(tok1)+"</code></td>", "<td>never")
		a.mustNotContain(r, tok1)

		r = a.post("/service-accounts/"+svc+"/tokens", url.Values{"label": {"second"}, "expiry": {"30d"}})
		tok2 := revealedToken(r.Body)
		if tok2 == "" {
			t.Fatal("second token not revealed")
		}
		if st := ntfyRequest(t, ntfyURL, tok1, topic, "old token still valid after password rotation"); st != http.StatusOK {
			t.Fatalf("existing token must survive password rotation: %d", st)
		}

		r = a.get("/service-accounts/" + svc)
		r = a.post("/service-accounts/"+svc+"/tokens/revoke", url.Values{"idx": {tokenIndex(t, r.Body, tok1)}, "masked": {ntfyapi.MaskToken(tok1)}})
		a.mustContain(r, "Token "+ntfyapi.MaskToken(tok1)+" revoked.")
		a.mustNotContain(r, "<code>"+ntfyapi.MaskToken(tok1)+"</code>")
		if st := ntfyRequest(t, ntfyURL, tok1, topic, "must fail"); st == http.StatusOK {
			t.Fatal("publish with revoked token must fail")
		}
		if st := ntfyRequest(t, ntfyURL, tok2, topic, "second token"); st != http.StatusOK {
			t.Fatalf("other token must remain valid: %d", st)
		}

		a.post("/service-accounts/"+svc+"/disable", nil)
		if st := ntfyRequest(t, ntfyURL, tok2, topic, "must fail"); st == http.StatusOK {
			t.Fatal("publish must be denied after disabling (auth-default-access: deny-all)")
		}

		a.post("/service-accounts/"+svc+"/delete", nil)
		users, _ := api.Users(ctx, admin)
		if _, ok := findUser(users, svc); ok {
			t.Fatal("service account not deleted")
		}
	})

	t.Run("admin is protected", func(t *testing.T) {
		r := a.post("/users/"+admin.Username+"/delete", nil)
		a.mustContain(r, "not a regular user")
	})

	t.Run("logout revokes session token", func(t *testing.T) {
		a.post("/logout", nil)
		if n := countSessionTokens(); n != before {
			t.Fatalf("session tokens after logout: %d, want %d", n, before)
		}
	})
}

// TestIntegrationNoUserMixup guards against ntfy v2.29.0's per-IP visitor
// race: while an admin uses ntfy-admin, a regular user logging in must never
// end up with the admin's identity. ntfy-admin prevents it by serializing
// its requests to ntfy and by verifying every token it creates.
func TestIntegrationNoUserMixup(t *testing.T) {
	ntfyURL, admin := integrationEnv(t)
	ctx := context.Background()
	api := ntfyapi.New(ntfyURL, nil)
	mallory := fmt.Sprintf("it-mallory-%d", time.Now().UnixNano()%1_000_000_000)
	if err := api.AddUser(ctx, admin, mallory, "pw-m"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = api.DeleteUser(ctx, admin, mallory) })

	a := newApp(t, ntfyURL, nil)
	a.srv.limiter.perKey, a.srv.limiter.global = 1_000_000, 1_000_000 // not under test here
	if r := a.login(admin.Username, admin.Password); r.Path != "/users" {
		t.Fatal("admin login failed")
	}
	m := a.clone()
	m.get("/login")

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { // admin traffic
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				req, _ := http.NewRequest(http.MethodGet, a.ts.URL+"/users", nil)
				if resp, err := a.client.Do(req); err == nil {
					resp.Body.Close()
				}
			}
		}
	}()
	for i := range 60 {
		_, body, err := m.rawPost("/login", url.Values{"username": {mallory}, "password": {"pw-m"}, "csrf": {m.csrf}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(body, "Log out") {
			close(stop)
			<-done
			t.Fatalf("attempt %d: a regular user got an admin session", i)
		}
	}
	close(stop)
	<-done
	acc, err := api.Account(ctx, ntfyapi.Basic{Username: mallory, Password: "pw-m"})
	if err != nil || len(acc.Tokens) != 0 {
		t.Fatalf("rejected logins must not leave tokens: %v %+v", err, acc)
	}
}

func hasGrant(gs []ntfyapi.Grant, topic, perm string) bool {
	for _, g := range gs {
		if g.Topic == topic && g.Permission == perm {
			return true
		}
	}
	return false
}
