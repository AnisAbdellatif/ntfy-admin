// Package ntfyfake is an in-memory fake of the ntfy admin/account HTTP API,
// for tests. It follows the behaviour of ntfy's server_admin.go and
// server_account.go closely enough to exercise ntfy-admin's error paths.
package ntfyfake

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"time"

	"ntfy-admin/internal/ntfyapi"
)

const maxTokens = 60

type user struct {
	name        string
	password    string
	role        string
	tier        string
	grants      []ntfyapi.Grant
	tokens      []ntfyapi.Token
	provisioned bool
}

type failure struct {
	status  int
	code    int
	message string
}

// Fake is an in-memory ntfy server.
type Fake struct {
	*httptest.Server

	mu       sync.Mutex
	users    map[string]*user
	order    []string
	failures map[string]failure // "METHOD /path" -> injected failure (one-shot)
	Calls    []string           // "METHOD /path" of every request, for assertions
}

// New starts a fake with the anonymous user "*" and one admin.
func New(adminName, adminPassword string) *Fake {
	f := &Fake{users: map[string]*user{}, failures: map[string]failure{}}
	f.addUser(&user{name: ntfyapi.Everyone, role: ntfyapi.RoleAnonymous})
	f.addUser(&user{name: adminName, password: adminPassword, role: ntfyapi.RoleAdmin, provisioned: true})
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

func (f *Fake) addUser(u *user) {
	f.users[u.name] = u
	f.order = append(f.order, u.name)
}

// AddRegularUser adds a user with role "user" directly (bypassing the API).
func (f *Fake) AddRegularUser(name, password string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addUser(&user{name: name, password: password, role: ntfyapi.RoleUser})
}

// AddProvisionedToken adds a token as if it came from server.yml auth-tokens.
func (f *Fake) AddProvisionedToken(username, token string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.users[username]
	u.tokens = append(u.tokens, ntfyapi.Token{Token: token, Label: "provisioned", Provisioned: true})
}

// FailNext makes the next request matching method+path fail with the given status.
func (f *Fake) FailNext(method, path string, status, code int, message string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures[method+" "+path] = failure{status, code, message}
}

// UserExists reports whether a user exists.
func (f *Fake) UserExists(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.users[name]
	return ok
}

// Password returns the current password of a user (to check rotation).
func (f *Fake) Password(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.users[name]; ok {
		return u.password
	}
	return ""
}

// Grants returns a copy of a user's grants.
func (f *Fake) Grants(name string) []ntfyapi.Grant {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.users[name]; ok {
		return slices.Clone(u.grants)
	}
	return nil
}

// Tokens returns a copy of a user's tokens.
func (f *Fake) Tokens(name string) []ntfyapi.Token {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, ok := f.users[name]; ok {
		return slices.Clone(u.tokens)
	}
	return nil
}

// TokenCount returns the total number of tokens across all users.
func (f *Fake) TokenCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, u := range f.users {
		n += len(u.tokens)
	}
	return n
}

// CountCalls returns how many requests matched "METHOD /path".
func (f *Fake) CountCalls(call string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.Calls {
		if c == call {
			n++
		}
	}
	return n
}

func writeErr(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "http": status, "error": msg})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func success(w http.ResponseWriter) { writeJSON(w, map[string]bool{"success": true}) }

func (f *Fake) authenticate(r *http.Request) (*user, bool) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return nil, true
	}
	if tok, ok := strings.CutPrefix(h, "Bearer "); ok {
		now := time.Now().Unix()
		for _, u := range f.users {
			for _, t := range u.tokens {
				if t.Token == tok && (t.Expires == 0 || t.Expires > now) {
					return u, true
				}
			}
		}
		return nil, false
	}
	if name, pass, ok := r.BasicAuth(); ok {
		if u, exists := f.users[name]; exists && u.role != ntfyapi.RoleAnonymous && u.password == pass {
			return u, true
		}
	}
	return nil, false
}

func newToken() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 29)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return "tk_" + string(b)
}

func (f *Fake) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := r.Method + " " + r.URL.Path
	f.Calls = append(f.Calls, key)
	if fl, ok := f.failures[key]; ok {
		delete(f.failures, key)
		writeErr(w, fl.status, fl.code, fl.message)
		return
	}
	if key == "GET /v1/health" {
		writeJSON(w, map[string]bool{"healthy": true})
		return
	}
	u, ok := f.authenticate(r)
	if !ok {
		writeErr(w, 401, 40101, "unauthorized")
		return
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/v1/users"):
		if u == nil || u.role != ntfyapi.RoleAdmin {
			writeErr(w, 401, 40101, "unauthorized")
			return
		}
		f.serveAdmin(w, r, key)
	case strings.HasPrefix(r.URL.Path, "/v1/account"):
		if u == nil {
			writeErr(w, 401, 40101, "unauthorized")
			return
		}
		f.serveAccount(w, r, key, u)
	default:
		writeErr(w, 404, 40401, "page not found")
	}
}

type body struct {
	Username   string  `json:"username"`
	Password   string  `json:"password"`
	Tier       string  `json:"tier"`
	Topic      string  `json:"topic"`
	Permission string  `json:"permission"`
	Label      *string `json:"label"`
	Expires    *int64  `json:"expires"`
}

func readBody(r *http.Request, allowEmpty bool) (*body, bool) {
	var b body
	err := json.NewDecoder(r.Body).Decode(&b)
	if err != nil && !(allowEmpty && errors.Is(err, io.EOF)) {
		return nil, false
	}
	return &b, true
}

func (f *Fake) serveAdmin(w http.ResponseWriter, r *http.Request, key string) {
	if key == "GET /v1/users" {
		out := []ntfyapi.User{}
		for _, name := range f.order {
			u := f.users[name]
			out = append(out, ntfyapi.User{Username: u.name, Role: u.role, Tier: u.tier, Grants: slices.Clone(u.grants)})
		}
		writeJSON(w, out)
		return
	}
	b, ok := readBody(r, false)
	if !ok {
		writeErr(w, 400, 40024, "invalid request: request body must be JSON")
		return
	}
	target := f.users[b.Username]
	switch key {
	case "POST /v1/users":
		if !ntfyapi.ValidUsername(b.Username) || b.Password == "" {
			writeErr(w, 400, 40001, "invalid request: username invalid, or password/password_hash missing")
		} else if target != nil {
			writeErr(w, 409, 40901, "conflict: user already exists")
		} else {
			f.addUser(&user{name: b.Username, password: b.Password, role: ntfyapi.RoleUser, tier: b.Tier})
			success(w)
		}
	case "PUT /v1/users":
		if !ntfyapi.ValidUsername(b.Username) {
			writeErr(w, 400, 40001, "invalid request: username invalid")
		} else if b.Password == "" && b.Tier == "" {
			writeErr(w, 400, 40001, "invalid request: need to provide at least one of \"password\", \"password_hash\" or \"tier\"")
		} else if target != nil && target.role == ntfyapi.RoleAdmin {
			writeErr(w, 403, 40301, "forbidden")
		} else {
			if target == nil {
				target = &user{name: b.Username, role: ntfyapi.RoleUser}
				f.addUser(target)
			}
			if b.Password != "" {
				target.password = b.Password
			}
			if b.Tier != "" {
				target.tier = b.Tier
			}
			success(w)
		}
	case "DELETE /v1/users":
		if target == nil {
			writeErr(w, 400, 40019, "invalid request: user not found")
		} else if target.role != ntfyapi.RoleUser {
			writeErr(w, 401, 40101, "unauthorized: can only remove regular users from API")
		} else {
			delete(f.users, b.Username)
			f.order = slices.DeleteFunc(f.order, func(n string) bool { return n == b.Username })
			success(w)
		}
	case "PUT /v1/users/access", "POST /v1/users/access":
		if target == nil {
			writeErr(w, 400, 40019, "invalid request: user not found")
		} else if !ntfyapi.ValidPermission(b.Permission) {
			writeErr(w, 400, 40025, "invalid request: invalid permission")
		} else if !ntfyapi.ValidTopicPattern(b.Topic) {
			writeErr(w, 500, 50001, "internal server error")
		} else {
			i := slices.IndexFunc(target.grants, func(g ntfyapi.Grant) bool { return g.Topic == b.Topic })
			if i >= 0 {
				target.grants[i].Permission = b.Permission
			} else {
				target.grants = append(target.grants, ntfyapi.Grant{Topic: b.Topic, Permission: b.Permission})
			}
			success(w)
		}
	case "DELETE /v1/users/access":
		if target == nil {
			writeErr(w, 500, 50001, "internal server error")
		} else {
			if b.Topic == "" {
				target.grants = nil
			} else {
				target.grants = slices.DeleteFunc(target.grants, func(g ntfyapi.Grant) bool { return g.Topic == b.Topic })
			}
			success(w)
		}
	default:
		writeErr(w, 404, 40401, "page not found")
	}
}

func (f *Fake) serveAccount(w http.ResponseWriter, r *http.Request, key string, u *user) {
	switch key {
	case "GET /v1/account":
		writeJSON(w, ntfyapi.Account{Username: u.name, Role: u.role, Tokens: slices.Clone(u.tokens)})
	case "POST /v1/account/token":
		b, ok := readBody(r, true)
		if !ok {
			writeErr(w, 400, 40024, "invalid request: request body must be JSON")
			return
		}
		t := ntfyapi.Token{Token: newToken(), LastAccess: time.Now().Unix(), LastOrigin: "127.0.0.1"}
		t.Expires = time.Now().Add(72 * time.Hour).Unix()
		if b.Expires != nil {
			t.Expires = *b.Expires
		}
		if b.Label != nil {
			t.Label = *b.Label
		}
		u.tokens = append(u.tokens, t)
		if len(u.tokens) > maxTokens {
			u.tokens = u.tokens[len(u.tokens)-maxTokens:]
		}
		writeJSON(w, t)
	case "DELETE /v1/account/token":
		tok := r.Header.Get("X-Token")
		if tok == "" {
			writeErr(w, 400, 40035, "invalid request: no token provided")
			return
		}
		i := slices.IndexFunc(u.tokens, func(t ntfyapi.Token) bool { return t.Token == tok })
		if i >= 0 && u.tokens[i].Provisioned {
			writeErr(w, 409, 40903, "conflict: cannot change or delete provisioned token")
			return
		}
		if i >= 0 {
			u.tokens = slices.Delete(u.tokens, i, i+1)
		}
		success(w)
	default:
		writeErr(w, 404, 40401, fmt.Sprintf("page not found: %s", key))
	}
}
