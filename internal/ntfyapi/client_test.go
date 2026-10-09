package ntfyapi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"ntfy-admin/internal/ntfyapi"
	"ntfy-admin/internal/ntfyfake"
)

func TestClientAgainstFake(t *testing.T) {
	f := ntfyfake.New("admin", "adminpw")
	defer f.Close()
	c := ntfyapi.New(f.URL, nil)
	ctx := context.Background()

	ok, err := c.Health(ctx)
	if err != nil || !ok {
		t.Fatalf("health: %v %v", ok, err)
	}

	tok, err := c.CreateToken(ctx, ntfyapi.Basic{Username: "admin", Password: "adminpw"}, "test", 0)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if tok.Expires != 0 {
		t.Fatalf("expected never-expiring token, got %d", tok.Expires)
	}
	admin := ntfyapi.Bearer(tok.Token)

	users, err := c.Users(ctx, admin)
	if err != nil {
		t.Fatalf("users: %v", err)
	}
	if len(users) != 2 || !users[0].IsAnonymous() || !users[1].IsAdmin() {
		t.Fatalf("unexpected users: %+v", users)
	}

	if err := c.AddUser(ctx, admin, "phil", "pw", ""); err != nil {
		t.Fatalf("add user: %v", err)
	}
	if err := c.AddUser(ctx, admin, "phil", "pw", ""); !ntfyapi.IsConflict(err) {
		t.Fatalf("expected 409, got %v", err)
	}
	if err := c.Grant(ctx, admin, "phil", "alerts_*", ntfyapi.PermReadOnly); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if err := c.Grant(ctx, admin, ntfyapi.Everyone, "public", ntfyapi.PermReadOnly); err != nil {
		t.Fatalf("grant anonymous: %v", err)
	}
	if err := c.Revoke(ctx, admin, "phil", ""); err == nil {
		t.Fatal("Revoke with empty topic must be refused client-side")
	}
	if err := c.Revoke(ctx, admin, "phil", "alerts_*"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := c.UpdateUser(ctx, admin, "admin", "x", ""); !ntfyapi.IsForbidden(err) {
		t.Fatalf("expected 403 for admin update, got %v", err)
	}
	if err := c.DeleteUser(ctx, admin, "admin"); !ntfyapi.IsUnauthorized(err) {
		t.Fatalf("expected 401 for admin delete, got %v", err)
	}
	if err := c.DeleteUser(ctx, admin, "phil"); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := c.Users(ctx, ntfyapi.Bearer("tk_invalid")); !ntfyapi.IsUnauthorized(err) {
		t.Fatalf("expected 401 for bad token, got %v", err)
	}
	if err := c.DeleteToken(ctx, admin, tok.Token); err != nil {
		t.Fatalf("delete token: %v", err)
	}
	if f.TokenCount() != 0 {
		t.Fatalf("token not deleted")
	}
}

func TestErrorShapes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/users":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"code":40019,"http":400,"error":"invalid request: user not found","link":"https://ntfy.sh/docs"}`)
		default:
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, `<html>bad gateway</html>`)
		}
	}))
	defer srv.Close()
	c := ntfyapi.New(srv.URL, nil)

	_, err := c.Users(context.Background(), ntfyapi.Bearer("tk_x"))
	apiErr, ok := err.(*ntfyapi.APIError)
	if !ok || apiErr.Status != 400 || apiErr.Code != 40019 || apiErr.Link == "" || apiErr.Message != "invalid request: user not found" {
		t.Fatalf("unexpected error: %#v", err)
	}
	_, err = c.Account(context.Background(), ntfyapi.Bearer("tk_x"))
	if ntfyapi.StatusOf(err) != http.StatusBadGateway {
		t.Fatalf("expected 502 for non-JSON error, got %v", err)
	}
}

func TestCreateTokenAlwaysSendsExpires(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = io.WriteString(w, `{"token":"tk_abc"}`)
	}))
	defer srv.Close()
	c := ntfyapi.New(srv.URL, nil)
	if _, err := c.CreateToken(context.Background(), ntfyapi.Basic{Username: "u", Password: "p"}, "", 0); err != nil {
		t.Fatal(err)
	}
	if v, ok := got["expires"]; !ok || v.(float64) != 0 {
		t.Fatalf("expires must be sent explicitly as 0, body was %v", got)
	}
	if _, ok := got["label"]; ok {
		t.Fatalf("empty label should be omitted, body was %v", got)
	}
}

func TestDeleteTokenUsesHeader(t *testing.T) {
	var header string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Get("X-Token")
		_, _ = io.WriteString(w, `{"success":true}`)
	}))
	defer srv.Close()
	c := ntfyapi.New(srv.URL, nil)
	if err := c.DeleteToken(context.Background(), ntfyapi.Bearer("tk_a"), "tk_b"); err != nil {
		t.Fatal(err)
	}
	if header != "tk_b" {
		t.Fatalf("X-Token = %q", header)
	}
}

func TestValidation(t *testing.T) {
	cases := []struct {
		fn   func(string) bool
		in   string
		want bool
	}{
		{ntfyapi.ValidUsername, "phil.e+x@home_1-a", true},
		{ntfyapi.ValidUsername, "*", false},
		{ntfyapi.ValidUsername, "a b", false},
		{ntfyapi.ValidUsername, "", false},
		{ntfyapi.ValidACLUsername, "*", true},
		{ntfyapi.ValidTopic, "alerts_1-x", true},
		{ntfyapi.ValidTopic, "alerts_*", false},
		{ntfyapi.ValidTopicPattern, "alerts_*", true},
		{ntfyapi.ValidTopicPattern, "a/b", false},
		{ntfyapi.ValidTopicPattern, string(make([]byte, 65)), false},
		{ntfyapi.ValidPermission, "read-only", true},
		{ntfyapi.ValidPermission, "ro", false},
	}
	for _, c := range cases {
		if got := c.fn(c.in); got != c.want {
			t.Errorf("validate(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestMatchTopic(t *testing.T) {
	cases := []struct {
		pattern, topic string
		want           bool
	}{
		{"backup_*", "backup_nas", true},
		{"backup_*", "backup_", true},
		{"backup_*", "xbackup_nas", false},
		{"*", "anything", true},
		{"a*c", "abbbc", true},
		{"a*c", "abbbd", false},
		{"alerts", "alerts", true},
		{"al-rts", "al-rts", true},
	}
	for _, c := range cases {
		if got := ntfyapi.MatchTopic(c.pattern, c.topic); got != c.want {
			t.Errorf("MatchTopic(%q, %q) = %v, want %v", c.pattern, c.topic, got, c.want)
		}
	}
}

func TestMaskToken(t *testing.T) {
	if got := ntfyapi.MaskToken("tk_abcdefghijklmnopqrstuvwxyz123"); got != "tk_abcd…z123" {
		t.Fatalf("got %q", got)
	}
	if got := ntfyapi.MaskToken("short"); got != "tk_…" {
		t.Fatalf("got %q", got)
	}
}
