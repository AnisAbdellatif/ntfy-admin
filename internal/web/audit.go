package web

import (
	"errors"
	"net/http"
)

type errString string

func (e errString) Error() string { return string(e) }

// auditLog writes one structured line per mutation: actor, client IP, action,
// target and result. Never pass passwords or full tokens as target.
func (s *Server) auditLog(r *http.Request, actor, action, target string, err error) {
	result := "ok"
	attrs := []any{"actor", actor, "ip", s.clientIP(r), "action", action, "target", target}
	if err != nil {
		result = "error"
		var es errString
		if errors.As(err, &es) {
			result = "denied"
		}
		attrs = append(attrs, "error", err.Error())
	}
	attrs = append(attrs, "result", result)
	s.audit.Info("audit", attrs...)
}
