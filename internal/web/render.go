package web

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"ntfy-admin/internal/ntfyapi"
	"ntfy-admin/internal/session"
)

var pageNames = []string{"login", "users", "user", "topics", "svc_list", "svc", "error"}

type pageData struct {
	Title       string
	Page        string
	User        string
	CSRF        string
	Flashes     []session.Flash
	Permissions []string
	SvcPrefix   string
	Data        any
}

func (s *Server) parseTemplates() error {
	funcs := template.FuncMap{
		"url":       s.url,
		"userPath":  func(n string) string { return s.url(userPath(n)) },
		"svcPath":   func(n string) string { return s.url(svcPath(n)) },
		"mask":      ntfyapi.MaskToken,
		"isPattern": ntfyapi.IsPattern,
		"isSvc":     s.isSvc,
		"display":   displayName,
		"unix":      formatUnix,
		"permClass": func(p string) string { return "perm perm-" + p },
	}
	s.pages = map[string]*template.Template{}
	for _, name := range pageNames {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/partials.html", "templates/"+name+".html")
		if err != nil {
			return fmt.Errorf("parsing template %s: %w", name, err)
		}
		s.pages[name] = t
	}
	return nil
}

func displayName(username string) string {
	if username == ntfyapi.Everyone {
		return "Everyone (anonymous)"
	}
	return username
}

func formatUnix(ts int64) string {
	if ts == 0 {
		return "never"
	}
	return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04 UTC")
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, sess *session.Session, page, title string, data any) {
	s.renderStatus(w, r, sess, http.StatusOK, page, title, data)
}

func (s *Server) renderStatus(w http.ResponseWriter, r *http.Request, sess *session.Session, status int, page, title string, data any) {
	pd := pageData{
		Title:       title,
		Page:        page,
		Permissions: ntfyapi.Permissions,
		SvcPrefix:   s.cfg.SvcPrefix,
		Data:        data,
	}
	if sess != nil {
		pd.User = sess.Username
		pd.CSRF = sess.CSRF
		pd.Flashes = sess.PopFlashes()
	}
	var buf bytes.Buffer
	if err := s.pages[page].Execute(&buf, pd); err != nil {
		s.log.Error("rendering template", "page", page, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}
