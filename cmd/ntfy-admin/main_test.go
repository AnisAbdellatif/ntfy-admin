package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := loadConfig(nil, env(map[string]string{"NTFY_URL": "http://ntfy:80/"}))
	if err != nil {
		t.Fatal(err)
	}
	w := cfg.web
	if cfg.listen != ":8080" || w.NtfyURL != "http://ntfy:80" || !w.CookieSecure || w.SessionTTL != 12*time.Hour || w.SvcPrefix != "svc-" || w.BasePath != "" || len(w.TrustedProxies) != 0 {
		t.Fatalf("unexpected defaults: %+v %+v", cfg, w)
	}
}

func TestLoadConfigOverrides(t *testing.T) {
	cfg, err := loadConfig([]string{"-listen", ":9000"}, env(map[string]string{
		"NTFY_URL":        "https://ntfy.example.com",
		"LISTEN":          ":7000",
		"COOKIE_SECURE":   "false",
		"SESSION_TTL":     "1h",
		"SVC_PREFIX":      "bot.",
		"TRUSTED_PROXIES": "10.0.0.0/8, 192.168.1.1, ::1",
		"BASE_PATH":       "admin/",
	}))
	if err != nil {
		t.Fatal(err)
	}
	w := cfg.web
	if cfg.listen != ":9000" || w.CookieSecure || w.SessionTTL != time.Hour || w.SvcPrefix != "bot." || w.BasePath != "/admin" || len(w.TrustedProxies) != 3 {
		t.Fatalf("unexpected config: %+v %+v", cfg, w)
	}
}

func TestLoadConfigErrors(t *testing.T) {
	for name, e := range map[string]map[string]string{
		"missing url":   {},
		"bad url":       {"NTFY_URL": "ntfy:80"},
		"bad bool":      {"NTFY_URL": "http://ntfy", "COOKIE_SECURE": "maybe"},
		"short ttl":     {"NTFY_URL": "http://ntfy", "SESSION_TTL": "1m"},
		"bad prefix":    {"NTFY_URL": "http://ntfy", "SVC_PREFIX": "svc/"},
		"bad cidr":      {"NTFY_URL": "http://ntfy", "TRUSTED_PROXIES": "10.0.0.0/99"},
		"bad publicurl": {"NTFY_URL": "http://ntfy", "NTFY_PUBLIC_URL": "ftp://x"},
	} {
		if _, err := loadConfig(nil, env(e)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestHealthcheckHonoursFlagsAndEnv(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/healthz" {
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")
	if code := healthcheck([]string{"-listen", addr, "-base-path", "/admin"}, env(nil)); code != 0 {
		t.Fatalf("flags: exit %d", code)
	}
	if code := healthcheck(nil, env(map[string]string{"LISTEN": addr, "BASE_PATH": "admin/"})); code != 0 {
		t.Fatalf("env: exit %d", code)
	}
	if code := healthcheck([]string{"-listen", addr}, env(nil)); code != 1 {
		t.Fatalf("wrong base path must fail, exit %d", code)
	}
}
