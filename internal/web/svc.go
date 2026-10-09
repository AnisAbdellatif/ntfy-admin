package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ntfy-admin/internal/ntfyapi"
	"ntfy-admin/internal/session"
)

type svcRow struct {
	Username string
	Rules    []ntfyapi.Grant
}

type tokenRow struct {
	Index       int
	Masked      string
	Label       string
	Expires     int64
	Expired     bool
	LastAccess  int64
	LastOrigin  string
	Provisioned bool
}

func (s *Server) handleSvcList(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	users, err := s.fetchUsers(r.Context(), sess)
	if err != nil {
		s.pageFailed(w, r, sess, err)
		return
	}
	sortUsers(users)
	var rows []svcRow
	for _, u := range users {
		if s.isSvc(u.Username) && u.Role == ntfyapi.RoleUser {
			rows = append(rows, svcRow{Username: u.Username, Rules: sortGrants(u.Grants)})
		}
	}
	s.render(w, r, sess, "svc_list", "Service accounts", map[string]any{"Accounts": rows})
}

// parseExpiry turns the expiry form fields into unix seconds (0 = never).
func parseExpiry(r *http.Request, now time.Time) (int64, error) {
	switch r.PostForm.Get("expiry") {
	case "never":
		return 0, nil
	case "30d":
		return now.AddDate(0, 0, 30).Unix(), nil
	case "90d":
		return now.AddDate(0, 0, 90).Unix(), nil
	case "1y":
		return now.AddDate(1, 0, 0).Unix(), nil
	case "custom":
		d, err := time.Parse("2006-01-02", r.PostForm.Get("expiry_date"))
		if err != nil {
			return 0, errors.New("invalid custom expiry date")
		}
		t := d.Add(24*time.Hour - time.Second) // end of that day, UTC
		if !t.After(now) {
			return 0, errors.New("custom expiry date must be in the future")
		}
		return t.Unix(), nil
	}
	return 0, errors.New("choose a token expiry")
}

func parseLabel(r *http.Request) (string, error) {
	label := strings.TrimSpace(r.PostForm.Get("label"))
	if len(label) > 128 {
		return "", errors.New("token label is too long (max 128 characters)")
	}
	return label, nil
}

// svcName builds the full service account name from the form, enforcing the prefix.
func (s *Server) svcName(raw string) string {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(raw, s.cfg.SvcPrefix) {
		return raw
	}
	return s.cfg.SvcPrefix + raw
}

func (s *Server) handleSvcCreate(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	name := s.svcName(r.PostForm.Get("name"))
	now := time.Now()
	rules, rulesErr := parseRules(r)
	expires, expErr := parseExpiry(r, now)
	label, labelErr := parseLabel(r)
	if !ntfyapi.ValidUsername(name) || !s.isSvc(name) {
		sess.AddFlash("error", "Invalid name (allowed: letters, digits and - _ . + @).")
		s.redirect(w, r, "/service-accounts")
		return
	}
	if err := errors.Join(rulesErr, expErr, labelErr); err != nil {
		sess.AddFlash("error", err.Error())
		s.redirect(w, r, "/service-accounts")
		return
	}
	if _, exists, err := s.lookupUser(r.Context(), sess, name); err != nil {
		s.ntfyFailed(w, r, sess, "/service-accounts", err)
		return
	} else if exists {
		sess.AddFlash("error", fmt.Sprintf("User %q already exists.", name))
		s.redirect(w, r, "/service-accounts")
		return
	}

	// Random password: generated here, used once for the token call, never shown or stored.
	password := session.RandomString(32)
	err := s.ntfy.AddUser(r.Context(), ntfyapi.Bearer(sess.Token), name, password, "")
	s.auditLog(r, sess.Username, "svc.create", name, err)
	if ntfyapi.IsConflict(err) {
		sess.AddFlash("error", fmt.Sprintf("User %q already exists.", name))
		s.redirect(w, r, "/service-accounts")
		return
	} else if err != nil {
		s.ntfyFailed(w, r, sess, "/service-accounts", err)
		return
	}
	if err := s.applyRules(r, sess, name, rules); err != nil {
		sess.AddFlash("ok", fmt.Sprintf("Service account %q created, but not all rules were applied and no token was issued.", name))
		s.ntfyFailed(w, r, sess, svcPath(name), err)
		return
	}
	tok, err := s.ntfy.CreateToken(r.Context(), ntfyapi.Basic{Username: name, Password: password}, label, expires)
	if err != nil {
		s.auditLog(r, sess.Username, "svc.token.issue", name, err)
		sess.AddFlash("ok", fmt.Sprintf("Service account %q created, but issuing the token failed.", name))
		s.ntfyFailed(w, r, sess, svcPath(name), basicErr(err))
		return
	}
	s.auditLog(r, sess.Username, "svc.token.issue", name+" "+ntfyapi.MaskToken(tok.Token), nil)
	sess.SetReveal(&session.Reveal{Account: name, Token: tok.Token, Label: tok.Label, Expires: tok.Expires})
	sess.AddFlash("ok", fmt.Sprintf("Service account %q created with %d rule(s).", name, len(rules)))
	s.redirect(w, r, svcPath(name))
}

// basicErr rewrites a 401 from a call authenticated as a service account, so
// that it is not mistaken for an expired admin session.
func basicErr(err error) error {
	if ntfyapi.IsUnauthorized(err) {
		return errString("ntfy rejected the service account credentials: " + err.Error())
	}
	return err
}

var (
	errNoSuchUser = errors.New("no such user")
	errNotSvc     = errors.New("not a service account")
)

// requireSvc checks that name is an existing, regular service account. It
// must run before any PUT /v1/users, because ntfy creates missing users there.
func (s *Server) requireSvc(ctx context.Context, sess *session.Session, name string) (ntfyapi.User, error) {
	if !s.isSvc(name) || !ntfyapi.ValidUsername(name) {
		return ntfyapi.User{}, errNotSvc
	}
	u, ok, err := s.lookupUser(ctx, sess, name)
	if err != nil {
		return u, err
	} else if !ok {
		return u, errNoSuchUser
	} else if u.Role != ntfyapi.RoleUser {
		return u, errNotSvc
	}
	return u, nil
}

// svcAuth sets a fresh random password on a service account and returns
// Basic credentials for it. Existing tokens stay valid; the password is
// discarded after the request.
func (s *Server) svcAuth(r *http.Request, sess *session.Session, name string) (ntfyapi.Basic, error) {
	password := session.RandomString(32)
	err := s.ntfy.UpdateUser(r.Context(), ntfyapi.Bearer(sess.Token), name, password, "")
	s.auditLog(r, sess.Username, "svc.rotate-password", name, err)
	return ntfyapi.Basic{Username: name, Password: password}, err
}

// svcPrecheck runs requireSvc and handles its errors for POST handlers.
func (s *Server) svcPrecheck(w http.ResponseWriter, r *http.Request, sess *session.Session, name string) bool {
	_, err := s.requireSvc(r.Context(), sess, name)
	switch {
	case err == nil:
		return true
	case errors.Is(err, errNoSuchUser):
		sess.AddFlash("error", fmt.Sprintf("Service account %q does not exist.", name))
		s.redirect(w, r, "/service-accounts")
	case errors.Is(err, errNotSvc):
		sess.AddFlash("error", fmt.Sprintf("%q is not a service account; tokens are only managed for regular users named %s….", name, s.cfg.SvcPrefix))
		s.redirect(w, r, "/service-accounts")
	default:
		s.ntfyFailed(w, r, sess, "/service-accounts", err)
	}
	return false
}

func (s *Server) handleSvc(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	name := r.PathValue("name")
	u, err := s.requireSvc(r.Context(), sess, name)
	switch {
	case errors.Is(err, errNoSuchUser):
		s.notFound(w, r, sess, fmt.Sprintf("Service account %q does not exist.", name))
		return
	case errors.Is(err, errNotSvc):
		s.notFound(w, r, sess, fmt.Sprintf("%q is not a service account.", name))
		return
	case err != nil:
		s.pageFailed(w, r, sess, err)
		return
	}
	data := map[string]any{
		"Account": u,
		"Rules":   sortGrants(u.Grants),
		"Reveal":  sess.PopReveal(name),
		"NtfyURL": s.cfg.NtfyPublicURL,
		"Example": exampleFor(u.Grants),
		"MinDate": time.Now().AddDate(0, 0, 1).Format("2006-01-02"),
	}
	auth, err := s.svcAuth(r, sess, name)
	if err == nil {
		var acc *ntfyapi.Account
		acc, err = s.ntfy.Account(r.Context(), auth)
		if err == nil {
			now := time.Now().Unix()
			refs := make([]string, len(acc.Tokens))
			rows := make([]tokenRow, len(acc.Tokens))
			for i, t := range acc.Tokens {
				refs[i] = t.Token
				rows[i] = tokenRow{
					Index: i, Masked: ntfyapi.MaskToken(t.Token), Label: t.Label,
					Expires: t.Expires, Expired: t.Expires != 0 && t.Expires <= now,
					LastAccess: t.LastAccess, LastOrigin: t.LastOrigin, Provisioned: t.Provisioned,
				}
			}
			sess.SetTokenRefs(name, refs)
			data["Tokens"] = rows
		} else {
			err = basicErr(err)
		}
	}
	if err != nil {
		if ntfyapi.IsUnauthorized(err) {
			s.pageFailed(w, r, sess, err)
			return
		}
		data["TokenError"] = describeErr(err)
	}
	s.render(w, r, sess, "svc", name, data)
}

// example picks a topic for the curl examples and which of them apply.
type example struct {
	Topic    string
	CanWrite bool
	CanRead  bool
}

func exampleFor(grants []ntfyapi.Grant) example {
	for _, g := range grants {
		if !ntfyapi.IsPattern(g.Topic) && g.Permission != ntfyapi.PermDenyAll {
			return example{
				Topic:    g.Topic,
				CanWrite: g.Permission == ntfyapi.PermReadWrite || g.Permission == ntfyapi.PermWriteOnly,
				CanRead:  g.Permission == ntfyapi.PermReadWrite || g.Permission == ntfyapi.PermReadOnly,
			}
		}
	}
	return example{Topic: "mytopic", CanWrite: true, CanRead: true}
}

func (s *Server) handleSvcTokenIssue(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	name := r.PathValue("name")
	back := svcPath(name)
	expires, expErr := parseExpiry(r, time.Now())
	label, labelErr := parseLabel(r)
	if err := errors.Join(expErr, labelErr); err != nil {
		sess.AddFlash("error", err.Error())
		s.redirect(w, r, back)
		return
	}
	if !s.svcPrecheck(w, r, sess, name) {
		return
	}
	auth, err := s.svcAuth(r, sess, name)
	if err != nil {
		s.ntfyFailed(w, r, sess, back, err)
		return
	}
	tok, err := s.ntfy.CreateToken(r.Context(), auth, label, expires)
	if err != nil {
		s.auditLog(r, sess.Username, "svc.token.issue", name, err)
		s.ntfyFailed(w, r, sess, back, basicErr(err))
		return
	}
	s.auditLog(r, sess.Username, "svc.token.issue", name+" "+ntfyapi.MaskToken(tok.Token), nil)
	sess.SetReveal(&session.Reveal{Account: name, Token: tok.Token, Label: tok.Label, Expires: tok.Expires})
	sess.AddFlash("ok", "Token issued.")
	s.redirect(w, r, back)
}

func (s *Server) handleSvcTokenRevoke(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	name := r.PathValue("name")
	back := svcPath(name)
	// The index refers to the list this session last displayed; the masked
	// value guards against a stale page pointing at a different token.
	idx, err := strconv.Atoi(r.PostForm.Get("idx"))
	token, ok := sess.TokenRef(name, idx)
	if err != nil || !ok || ntfyapi.MaskToken(token) != r.PostForm.Get("masked") {
		sess.AddFlash("error", "Unknown token; the list may have changed. Please try again.")
		s.redirect(w, r, back)
		return
	}
	if !s.svcPrecheck(w, r, sess, name) {
		return
	}
	auth, err := s.svcAuth(r, sess, name)
	if err != nil {
		s.ntfyFailed(w, r, sess, back, err)
		return
	}
	err = s.ntfy.DeleteToken(r.Context(), auth, token)
	s.auditLog(r, sess.Username, "svc.token.revoke", name+" "+ntfyapi.MaskToken(token), err)
	if ntfyapi.IsConflict(err) {
		sess.AddFlash("error", "This token is provisioned in server.yml (auth-tokens) and cannot be revoked here.")
		s.redirect(w, r, back)
		return
	} else if err != nil {
		s.ntfyFailed(w, r, sess, back, basicErr(err))
		return
	}
	sess.SetTokenRefs(name, nil)
	sess.AddFlash("ok", fmt.Sprintf("Token %s revoked.", ntfyapi.MaskToken(token)))
	s.redirect(w, r, back)
}

func (s *Server) handleSvcDisable(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	name := r.PathValue("name")
	back := svcPath(name)
	if !s.svcPrecheck(w, r, sess, name) {
		return
	}
	err := s.ntfy.RevokeAll(r.Context(), ntfyapi.Bearer(sess.Token), name)
	s.auditLog(r, sess.Username, "svc.disable", name, err)
	if err != nil {
		s.ntfyFailed(w, r, sess, back, err)
		return
	}
	sess.AddFlash("ok", fmt.Sprintf("Service account %q disabled: all rules revoked. Its tokens now only get auth-default-access.", name))
	s.redirect(w, r, back)
}

func (s *Server) handleSvcDelete(w http.ResponseWriter, r *http.Request, sess *session.Session) {
	name := r.PathValue("name")
	if !s.svcPrecheck(w, r, sess, name) {
		return
	}
	err := s.ntfy.DeleteUser(r.Context(), ntfyapi.Bearer(sess.Token), name)
	s.auditLog(r, sess.Username, "svc.delete", name, err)
	if err != nil {
		s.ntfyFailed(w, r, sess, svcPath(name), err)
		return
	}
	sess.AddFlash("ok", fmt.Sprintf("Service account %q deleted.", name))
	s.redirect(w, r, "/service-accounts")
}
