package web

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"ntfy-admin/internal/ntfyapi"
)

// syncBuffer is a goroutine-safe bytes.Buffer for capturing logs.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// testApp drives ntfy-admin through HTTP like a browser would.
type testApp struct {
	t      *testing.T
	srv    *Server
	ts     *httptest.Server
	client *http.Client
	audit  *syncBuffer
	logs   *syncBuffer
	csrf   string
	base   string
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func newApp(t *testing.T, ntfyURL string, mod func(*Config)) *testApp {
	t.Helper()
	cfg := Config{NtfyURL: ntfyURL, CookieSecure: false}
	if mod != nil {
		mod(&cfg)
	}
	audit, logs := &syncBuffer{}, &syncBuffer{}
	srv, err := New(cfg, ntfyapi.New(ntfyURL, nil), slog.New(slog.NewJSONHandler(logs, nil)), slog.New(slog.NewJSONHandler(audit, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(srv.Sessions().Shutdown) // revoke leftover session tokens, even if a test fails early
	jar, _ := cookiejar.New(nil)
	return &testApp{t: t, srv: srv, ts: ts, client: &http.Client{Jar: jar}, audit: audit, logs: logs, base: srv.cfg.BasePath}
}

type result struct {
	Status int
	Body   string
	Path   string // final path after redirects
	Header http.Header
}

func (a *testApp) do(req *http.Request) result {
	a.t.Helper()
	resp, err := a.client.Do(req)
	if err != nil {
		a.t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	body := string(b)
	if m := csrfRe.FindStringSubmatch(body); m != nil {
		a.csrf = m[1]
	}
	p := resp.Request.URL.Path
	if resp.Request.URL.RawQuery != "" {
		p += "?" + resp.Request.URL.RawQuery
	}
	return result{Status: resp.StatusCode, Body: body, Path: p, Header: resp.Header}
}

func (a *testApp) get(path string) result {
	a.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, a.ts.URL+a.base+path, nil)
	return a.do(req)
}

// post submits a form; the current CSRF token is added unless the form sets one.
func (a *testApp) post(path string, form url.Values) result {
	a.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if _, ok := form["csrf"]; !ok {
		form.Set("csrf", a.csrf)
	}
	req, _ := http.NewRequest(http.MethodPost, a.ts.URL+a.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return a.do(req)
}

func (a *testApp) login(user, pass string) result {
	a.t.Helper()
	a.get("/login")
	return a.post("/login", url.Values{"username": {user}, "password": {pass}})
}

func (a *testApp) mustContain(r result, subs ...string) {
	a.t.Helper()
	for _, s := range subs {
		if !strings.Contains(r.Body, s) {
			a.t.Fatalf("expected %q in response (status %d, path %s):\n%s", s, r.Status, r.Path, r.Body)
		}
	}
}

func (a *testApp) mustNotContain(r result, subs ...string) {
	a.t.Helper()
	for _, s := range subs {
		if strings.Contains(r.Body, s) {
			a.t.Fatalf("did not expect %q in response (status %d, path %s)", s, r.Status, r.Path)
		}
	}
}

// revealedToken extracts the token shown once after issuing it.
var revealRe = regexp.MustCompile(`<code id="new-token">(tk_[A-Za-z0-9_-]+)</code>`)

func revealedToken(body string) string {
	if m := revealRe.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}
