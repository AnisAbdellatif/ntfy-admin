package web

import (
	"fmt"
	"net/http"
	"slices"
	"strings"

	"ntfy-admin/internal/ntfyapi"
	"ntfy-admin/internal/session"
)

type userRow struct {
	ntfyapi.User
	Rules int
	IsSvc bool
}

func sortUsers(users []ntfyapi.User) {
	rank := func(u ntfyapi.User) int {
		switch {
		case u.IsAnonymous():
			return 0
		case u.IsAdmin():
			return 1
		}
		return 2
	}
	slices.SortStableFunc(users, func(a, b ntfyapi.User) int {
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra - rb
		}
		return strings.Compare(a.Username, b.Username)
	})
}

func sortGrants(gs []ntfyapi.Grant) []ntfyapi.Grant {
	gs = slices.Clone(gs)
	slices.SortFunc(gs, func(a, b ntfyapi.Grant) int { return strings.Compare(a.Topic, b.Topic) })
	return gs
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	users, err := s.fetchUsers(r.Context(), sess)
	if err != nil {
		s.pageFailed(w, r, sess, err)
		return
	}
	sortUsers(users)
	rows := make([]userRow, 0, len(users))
	for _, u := range users {
		rows = append(rows, userRow{User: u, Rules: len(u.Grants), IsSvc: s.isSvc(u.Username)})
	}
	s.render(w, r, sess, "users", "Users", map[string]any{"Users": rows})
}

// ruleInput is one (topic, permission) row of a form.
type ruleInput struct {
	Topic      string
	Permission string
}

// maxRules caps the rule rows of one form, which keeps the number of ntfy
// calls per request (and thus its duration) bounded.
const maxRules = 20

// parseRules reads repeated "topic"/"permission" form fields, skipping blank rows.
func parseRules(r *http.Request) ([]ruleInput, error) {
	topics, perms := r.PostForm["topic"], r.PostForm["permission"]
	var rules []ruleInput
	for i, t := range topics {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		p := ""
		if i < len(perms) {
			p = perms[i]
		}
		if !ntfyapi.ValidTopicPattern(t) {
			return nil, fmt.Errorf("invalid topic or pattern %q (allowed: letters, digits, - _ and * as wildcard, max 64)", t)
		}
		if !ntfyapi.ValidPermission(p) {
			return nil, fmt.Errorf("invalid permission %q", p)
		}
		rules = append(rules, ruleInput{Topic: t, Permission: p})
		if len(rules) > maxRules {
			return nil, fmt.Errorf("too many rules in one form (max %d); add the rest afterwards", maxRules)
		}
	}
	return rules, nil
}

// applyRules grants each rule, auditing each call. It stops at the first error.
func (s *Server) applyRules(r *http.Request, sess *session.Session, username string, rules []ruleInput) error {
	for _, rule := range rules {
		err := s.ntfy.Grant(r.Context(), ntfyapi.Bearer(sess.Token), username, rule.Topic, rule.Permission)
		s.auditLog(r, sess.Username, "access.grant", fmt.Sprintf("%s %s %s", username, rule.Topic, rule.Permission), err)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleUserAdd(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	username := strings.TrimSpace(r.PostForm.Get("username"))
	password := r.PostForm.Get("password")
	switch {
	case !ntfyapi.ValidUsername(username):
		sess.AddFlash("error", "Invalid username (allowed: letters, digits and - _ . + @).")
	case s.isSvc(username):
		sess.AddFlash("error", fmt.Sprintf("Names starting with %q are reserved for service accounts. Create it on the Service accounts page.", s.cfg.SvcPrefix))
	case password == "":
		sess.AddFlash("error", "A password is required.")
	}
	rules, err := parseRules(r)
	if err != nil {
		sess.AddFlash("error", err.Error())
	}
	if err != nil || !ntfyapi.ValidUsername(username) || s.isSvc(username) || password == "" {
		s.redirect(w, r, "/users")
		return
	}
	err = s.ntfy.AddUser(r.Context(), ntfyapi.Bearer(sess.Token), username, password)
	s.auditLog(r, sess.Username, "user.add", username, err)
	if ntfyapi.IsConflict(err) {
		sess.AddFlash("error", fmt.Sprintf("User %q already exists.", username))
		s.redirect(w, r, "/users")
		return
	} else if err != nil {
		s.ntfyFailed(w, r, sess, "/users", err)
		return
	}
	if err := s.applyRules(r, sess, username, rules); err != nil {
		sess.AddFlash("ok", fmt.Sprintf("User %q created.", username))
		s.ntfyFailed(w, r, sess, userPath(username), err)
		return
	}
	sess.AddFlash("ok", fmt.Sprintf("User %q created with %d rule(s).", username, len(rules)))
	s.redirect(w, r, userPath(username))
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	name := nameParam(r)
	users, err := s.fetchUsers(r.Context(), sess)
	if err != nil {
		s.pageFailed(w, r, sess, err)
		return
	}
	u, ok := findUser(users, name)
	if !ok {
		s.notFound(w, r, sess, fmt.Sprintf("User %q does not exist.", name))
		return
	}
	s.render(w, r, sess, "user", displayName(u.Username), map[string]any{
		"User":     u,
		"Rules":    sortGrants(u.Grants),
		"IsSvc":    s.isSvc(u.Username) && u.Role == ntfyapi.RoleUser,
		"Editable": !u.IsAdmin(),
	})
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request, sess *session.Session, msg string) {
	s.renderStatus(w, r, sess, http.StatusNotFound, "error", "Not found", map[string]any{"Message": msg})
}

// backPath maps the "back" form field to a safe local path.
func (s *Server) backPath(r *http.Request, username string) string {
	switch r.PostForm.Get("back") {
	case "users":
		return "/users"
	case "topics":
		return topicBack(r.PostForm.Get("anchor"))
	case "svc":
		if s.isSvc(username) {
			return svcPath(username)
		}
	}
	return userPath(username)
}

// requireRegular loads a user and checks that it is a regular (non-admin,
// non-anonymous) user. It flashes and redirects on failure.
func (s *Server) requireRegular(w http.ResponseWriter, r *http.Request, sess *session.Session, name, back string) bool {
	u, ok, err := s.lookupUser(r.Context(), sess, name)
	if err != nil {
		s.ntfyFailed(w, r, sess, back, err)
		return false
	}
	if !ok {
		sess.AddFlash("error", fmt.Sprintf("User %q does not exist.", name))
		s.redirect(w, r, "/users")
		return false
	}
	if u.Role != ntfyapi.RoleUser {
		sess.AddFlash("error", fmt.Sprintf("%q is not a regular user; admins are managed in server.yml / CLI.", displayName(name)))
		s.redirect(w, r, back)
		return false
	}
	return true
}

func (s *Server) handleUserPassword(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	name := nameParam(r)
	back := s.backPath(r, name)
	password := r.PostForm.Get("password")
	if password == "" {
		sess.AddFlash("error", "A password is required.")
		s.redirect(w, r, back)
		return
	}
	if s.isSvc(name) {
		// A known password would defeat the point of a token-only account.
		sess.AddFlash("error", "Service accounts have no usable password; manage their tokens instead.")
		s.redirect(w, r, back)
		return
	}
	defer s.locks.lock(name)()
	if !s.requireRegular(w, r, sess, name, back) {
		return
	}
	// requireRegular checked existence just now, under the per-user lock:
	// ntfy would create a missing user here.
	err := s.ntfy.SetPassword(r.Context(), ntfyapi.Bearer(sess.Token), name, password)
	s.auditLog(r, sess.Username, "user.password", name, err)
	if err != nil {
		s.ntfyFailed(w, r, sess, back, provisionedHint(err))
		return
	}
	sess.AddFlash("ok", fmt.Sprintf("Password of %q changed. Existing tokens of this user stay valid.", name))
	s.redirect(w, r, back)
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	name := nameParam(r)
	back := "/users"
	if r.PostForm.Get("back") == "svc" {
		back = "/service-accounts"
	}
	defer s.locks.lock(name)()
	if !s.requireRegular(w, r, sess, name, back) {
		return
	}
	err := s.ntfy.DeleteUser(r.Context(), ntfyapi.Bearer(sess.Token), name)
	s.auditLog(r, sess.Username, "user.delete", name, err)
	if err != nil {
		s.ntfyFailed(w, r, sess, back, provisionedHint(err))
		return
	}
	sess.AddFlash("ok", fmt.Sprintf("User %q deleted.", name))
	s.redirect(w, r, back)
}

// requireGrantable loads a user and checks that ACL changes are possible
// (regular users and anonymous; not admins).
func (s *Server) requireGrantable(w http.ResponseWriter, r *http.Request, sess *session.Session, name, back string) bool {
	if !ntfyapi.ValidACLUsername(name) {
		sess.AddFlash("error", "Invalid username.")
		s.redirect(w, r, back)
		return false
	}
	u, ok, err := s.lookupUser(r.Context(), sess, name)
	if err != nil {
		s.ntfyFailed(w, r, sess, back, err)
		return false
	}
	if !ok {
		sess.AddFlash("error", fmt.Sprintf("User %q does not exist.", name))
		s.redirect(w, r, back)
		return false
	}
	if u.IsAdmin() {
		sess.AddFlash("error", fmt.Sprintf("%q is an admin; admins always have full access.", name))
		s.redirect(w, r, back)
		return false
	}
	return true
}

func (s *Server) grant(w http.ResponseWriter, r *http.Request, sess *session.Session, name, topic, perm, back string) {
	if !ntfyapi.ValidTopicPattern(topic) {
		sess.AddFlash("error", fmt.Sprintf("Invalid topic or pattern %q.", topic))
		s.redirect(w, r, back)
		return
	}
	if !ntfyapi.ValidPermission(perm) {
		sess.AddFlash("error", fmt.Sprintf("Invalid permission %q.", perm))
		s.redirect(w, r, back)
		return
	}
	if !s.requireGrantable(w, r, sess, name, back) {
		return
	}
	err := s.ntfy.Grant(r.Context(), ntfyapi.Bearer(sess.Token), name, topic, perm)
	s.auditLog(r, sess.Username, "access.grant", fmt.Sprintf("%s %s %s", name, topic, perm), err)
	if err != nil {
		s.ntfyFailed(w, r, sess, back, err)
		return
	}
	sess.AddFlash("ok", fmt.Sprintf("%s: %s on %q.", displayName(name), perm, topic))
	s.redirect(w, r, back)
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request, sess *session.Session, name, topic, back string) {
	if topic == "" || !ntfyapi.ValidTopicPattern(topic) {
		sess.AddFlash("error", fmt.Sprintf("Invalid topic or pattern %q.", topic))
		s.redirect(w, r, back)
		return
	}
	if !s.requireGrantable(w, r, sess, name, back) {
		return
	}
	err := s.ntfy.Revoke(r.Context(), ntfyapi.Bearer(sess.Token), name, topic)
	s.auditLog(r, sess.Username, "access.revoke", fmt.Sprintf("%s %s", name, topic), err)
	if err != nil {
		s.ntfyFailed(w, r, sess, back, err)
		return
	}
	sess.AddFlash("ok", fmt.Sprintf("Rule for %s on %q revoked.", displayName(name), topic))
	s.redirect(w, r, back)
}

func (s *Server) handleUserGrant(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	name := nameParam(r)
	s.grant(w, r, sess, name, strings.TrimSpace(r.PostForm.Get("topic")), r.PostForm.Get("permission"), s.backPath(r, name))
}

func (s *Server) handleUserRevoke(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	name := nameParam(r)
	s.revoke(w, r, sess, name, r.PostForm.Get("topic"), s.backPath(r, name))
}

func (s *Server) handleUserRevokeAll(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	name := nameParam(r)
	back := s.backPath(r, name)
	if r.PostForm.Get("confirm") != name {
		sess.AddFlash("error", "To revoke all rules, type the exact username into the confirmation field.")
		s.redirect(w, r, back)
		return
	}
	if !s.requireGrantable(w, r, sess, name, back) {
		return
	}
	err := s.ntfy.RevokeAll(r.Context(), ntfyapi.Bearer(sess.Token), name)
	s.auditLog(r, sess.Username, "access.revoke-all", name, err)
	if err != nil {
		s.ntfyFailed(w, r, sess, back, err)
		return
	}
	sess.AddFlash("ok", fmt.Sprintf("All rules of %s revoked.", displayName(name)))
	s.redirect(w, r, back)
}
