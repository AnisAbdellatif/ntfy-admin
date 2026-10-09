// Command ntfy-admin is a small web UI for administering a self-hosted ntfy
// server (users, access control, service-account tokens) via ntfy's HTTP API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ntfy-admin/internal/ntfyapi"
	"ntfy-admin/internal/web"
)

var version = "dev"

type config struct {
	web    web.Config
	listen string
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck(os.Getenv))
	}
	if err := run(os.Args[1:], os.Getenv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "ntfy-admin:", err)
		os.Exit(1)
	}
}

func envOr(getenv func(string) string, key, def string) string {
	if v := strings.TrimSpace(getenv(key)); v != "" {
		return v
	}
	return def
}

func loadConfig(args []string, getenv func(string) string) (*config, error) {
	fs := flag.NewFlagSet("ntfy-admin", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	ntfyURL := fs.String("ntfy-url", envOr(getenv, "NTFY_URL", ""), "base URL of the ntfy server (env NTFY_URL, required)")
	publicURL := fs.String("ntfy-public-url", envOr(getenv, "NTFY_PUBLIC_URL", ""), "ntfy URL shown in curl examples (env NTFY_PUBLIC_URL)")
	listen := fs.String("listen", envOr(getenv, "LISTEN", ":8080"), "listen address (env LISTEN)")
	cookieSecure := fs.String("cookie-secure", envOr(getenv, "COOKIE_SECURE", "true"), "set the Secure flag on cookies (env COOKIE_SECURE)")
	ttl := fs.String("session-ttl", envOr(getenv, "SESSION_TTL", "12h"), "session lifetime (env SESSION_TTL)")
	prefix := fs.String("svc-prefix", envOr(getenv, "SVC_PREFIX", "svc-"), "username prefix of service accounts (env SVC_PREFIX)")
	proxies := fs.String("trusted-proxies", envOr(getenv, "TRUSTED_PROXIES", ""), "comma-separated CIDRs whose X-Forwarded-For is trusted (env TRUSTED_PROXIES)")
	basePath := fs.String("base-path", envOr(getenv, "BASE_PATH", ""), "URL path prefix behind a reverse proxy, e.g. /admin (env BASE_PATH)")
	showVersion := fs.Bool("version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(os.Stderr)
			fs.PrintDefaults()
		}
		return nil, err
	}
	if *showVersion {
		fmt.Println("ntfy-admin", version)
		os.Exit(0)
	}

	cfg := &config{listen: *listen}
	if err := checkURL(*ntfyURL); err != nil {
		return nil, fmt.Errorf("NTFY_URL: %w", err)
	}
	if *publicURL != "" {
		if err := checkURL(*publicURL); err != nil {
			return nil, fmt.Errorf("NTFY_PUBLIC_URL: %w", err)
		}
	}
	secure, err := strconv.ParseBool(*cookieSecure)
	if err != nil {
		return nil, fmt.Errorf("COOKIE_SECURE: %w", err)
	}
	sessionTTL, err := time.ParseDuration(*ttl)
	if err != nil {
		return nil, fmt.Errorf("SESSION_TTL: %w", err)
	}
	if sessionTTL < 5*time.Minute {
		return nil, errors.New("SESSION_TTL: must be at least 5m")
	}
	if !ntfyapi.ValidUsername(*prefix) {
		return nil, fmt.Errorf("SVC_PREFIX: %q contains characters not allowed in ntfy usernames", *prefix)
	}
	trusted, err := parseCIDRs(*proxies)
	if err != nil {
		return nil, fmt.Errorf("TRUSTED_PROXIES: %w", err)
	}
	cfg.web = web.Config{
		NtfyURL:        strings.TrimRight(*ntfyURL, "/"),
		NtfyPublicURL:  *publicURL,
		BasePath:       web.NormalizeBasePath(*basePath),
		CookieSecure:   secure,
		SessionTTL:     sessionTTL,
		SvcPrefix:      *prefix,
		TrustedProxies: trusted,
		LoginMinDelay:  time.Second,
	}
	return cfg, nil
}

func checkURL(s string) error {
	if s == "" {
		return errors.New("required")
	}
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%q is not an http(s) URL", s)
	}
	return nil
}

func parseCIDRs(s string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			if ip := net.ParseIP(part); ip != nil && ip.To4() != nil {
				part += "/32"
			} else {
				part += "/128"
			}
		}
		_, n, err := net.ParseCIDR(part)
		if err != nil {
			return nil, err
		}
		nets = append(nets, n)
	}
	return nets, nil
}

func run(args []string, getenv func(string) string) error {
	cfg, err := loadConfig(args, getenv)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	audit := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	client := ntfyapi.New(cfg.web.NtfyURL, nil)
	srv, err := web.New(cfg.web, client, logger, audit)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hctx, hcancel := context.WithTimeout(ctx, 5*time.Second)
	if ok, err := client.Health(hctx); err != nil || !ok {
		logger.Warn("ntfy is not reachable or unhealthy (continuing)", "ntfy_url", cfg.web.NtfyURL, "err", err)
	}
	hcancel()

	stopJanitor := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				srv.Sessions().Sweep()
				srv.SweepLimiter()
			case <-stopJanitor:
				return
			}
		}
	}()

	httpSrv := &http.Server{
		Addr:              cfg.listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() {
		logger.Info("ntfy-admin listening", "version", version, "listen", cfg.listen, "ntfy_url", cfg.web.NtfyURL, "base_path", cfg.web.BasePath)
		errc <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		close(stopJanitor)
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down; revoking session tokens", "sessions", srv.Sessions().Len())
	close(stopJanitor)
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(sctx)
	srv.Sessions().Shutdown()
	return nil
}

// healthcheck is used by the container HEALTHCHECK (no shell or curl in the image).
func healthcheck(getenv func(string) string) int {
	listen := envOr(getenv, "LISTEN", ":8080")
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	u := "http://" + net.JoinHostPort(host, port) + web.NormalizeBasePath(getenv("BASE_PATH")) + "/healthz"
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(u)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}
