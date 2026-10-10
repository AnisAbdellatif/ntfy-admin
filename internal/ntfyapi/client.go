package ntfyapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Auth authenticates a request against ntfy.
type Auth interface {
	apply(r *http.Request)
}

// Bearer authenticates with an ntfy access token (tk_…).
type Bearer string

func (b Bearer) apply(r *http.Request) { r.Header.Set("Authorization", "Bearer "+string(b)) }

// Basic authenticates with username and password.
type Basic struct {
	Username string
	Password string
}

func (b Basic) apply(r *http.Request) { r.SetBasicAuth(b.Username, b.Password) }

// APIError is an error response from ntfy:
// {"code": <int>, "http": <status>, "error": "<message>", "link": "<url>"}.
type APIError struct {
	Status  int    `json:"http"`
	Code    int    `json:"code"`
	Message string `json:"error"`
	Link    string `json:"link,omitempty"`
}

func (e *APIError) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("ntfy: %s (http %d, code %d)", e.Message, e.Status, e.Code)
	}
	return fmt.Sprintf("ntfy: %s (http %d)", e.Message, e.Status)
}

// StatusOf returns the HTTP status of an *APIError in err's chain, or 0.
func StatusOf(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status
	}
	return 0
}

// IsUnauthorized reports whether ntfy answered 401.
func IsUnauthorized(err error) bool { return StatusOf(err) == http.StatusUnauthorized }

// IsForbidden reports whether ntfy answered 403.
func IsForbidden(err error) bool { return StatusOf(err) == http.StatusForbidden }

// IsConflict reports whether ntfy answered 409.
func IsConflict(err error) bool { return StatusOf(err) == http.StatusConflict }

// IsTooManyRequests reports whether ntfy answered 429 (rate limited).
func IsTooManyRequests(err error) bool { return StatusOf(err) == http.StatusTooManyRequests }

// IsServerError reports whether ntfy answered 500. ntfy uses it for some
// refusals, e.g. changing a user or token provisioned in server.yml.
func IsServerError(err error) bool { return StatusOf(err) == http.StatusInternalServerError }

// ErrWrongUser means ntfy answered for a different user than the one that
// authenticated. ntfy v2.29.0 can mix up users that share one client IP
// under concurrent requests; every token ntfy-admin creates is checked.
var ErrWrongUser = errors.New("ntfy answered for a different user than expected")

// Client talks to one ntfy server.
//
// Requests are serialized: ntfy keys anonymous and tier-less users by client
// IP, and concurrent requests from one IP with different identities can be
// attributed to the wrong user (ntfy v2.29.0). Since all of ntfy-admin's
// requests come from one IP, it never sends two at once.
type Client struct {
	baseURL string
	http    *http.Client
	sem     chan struct{}
}

// New creates a client for the ntfy server at baseURL (e.g. "http://ntfy:80").
func New(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient, sem: make(chan struct{}, 1)}
}

// BaseURL returns the configured ntfy base URL.
func (c *Client) BaseURL() string { return c.baseURL }

const maxResponseBytes = 4 << 20

func (c *Client) do(ctx context.Context, auth Auth, method, path string, header http.Header, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if auth != nil {
		auth.apply(req)
	}
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("ntfy: %s %s: %w", method, path, ctx.Err())
	}
	defer func() { <-c.sem }()
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("ntfy: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("ntfy: %s %s: reading response: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		apiErr := &APIError{}
		if json.Unmarshal(data, apiErr) != nil || apiErr.Message == "" {
			apiErr.Message = strings.TrimSpace(http.StatusText(resp.StatusCode))
		}
		apiErr.Status = resp.StatusCode
		return apiErr
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("ntfy: %s %s: decoding response: %w", method, path, err)
	}
	return nil
}

// Health calls GET /v1/health.
func (c *Client) Health(ctx context.Context) (bool, error) {
	var resp healthResponse
	if err := c.do(ctx, nil, http.MethodGet, "/v1/health", nil, nil, &resp); err != nil {
		return false, err
	}
	return resp.Healthy, nil
}

// Users calls GET /v1/users (admin only).
func (c *Client) Users(ctx context.Context, auth Auth) ([]User, error) {
	var users []User
	if err := c.do(ctx, auth, http.MethodGet, "/v1/users", nil, nil, &users); err != nil {
		return nil, err
	}
	return users, nil
}

// AddUser calls POST /v1/users. It always creates a regular user; 409 if it exists.
func (c *Client) AddUser(ctx context.Context, auth Auth, username, password string) error {
	return c.do(ctx, auth, http.MethodPost, "/v1/users", nil, &userAddRequest{Username: username, Password: password}, nil)
}

// SetPassword calls PUT /v1/users with a new password. Careful: ntfy creates
// the user if it does not exist, so callers must check existence first.
func (c *Client) SetPassword(ctx context.Context, auth Auth, username, password string) error {
	return c.do(ctx, auth, http.MethodPut, "/v1/users", nil, &userAddRequest{Username: username, Password: password}, nil)
}

// DeleteUser calls DELETE /v1/users (regular users only).
func (c *Client) DeleteUser(ctx context.Context, auth Auth, username string) error {
	return c.do(ctx, auth, http.MethodDelete, "/v1/users", nil, &userDeleteRequest{Username: username}, nil)
}

// Grant calls PUT /v1/users/access (upsert). username may be "*".
func (c *Client) Grant(ctx context.Context, auth Auth, username, topic, permission string) error {
	return c.do(ctx, auth, http.MethodPut, "/v1/users/access", nil, &accessRequest{Username: username, Topic: topic, Permission: permission}, nil)
}

// Revoke calls DELETE /v1/users/access for one topic or pattern. An empty
// topic is refused here; use RevokeAll to reset all of a user's rules.
func (c *Client) Revoke(ctx context.Context, auth Auth, username, topic string) error {
	if topic == "" {
		return errors.New("ntfyapi: Revoke with empty topic would reset all rules; use RevokeAll")
	}
	return c.do(ctx, auth, http.MethodDelete, "/v1/users/access", nil, &accessRequest{Username: username, Topic: topic}, nil)
}

// RevokeAll calls DELETE /v1/users/access with an empty topic, which resets
// all of the user's rules.
func (c *Client) RevokeAll(ctx context.Context, auth Auth, username string) error {
	return c.do(ctx, auth, http.MethodDelete, "/v1/users/access", nil, &accessRequest{Username: username}, nil)
}

// CreateToken calls POST /v1/account/token as the authenticated user.
// expires is unix seconds; 0 means never. It is always sent explicitly, since
// ntfy defaults to 72h when it is omitted.
func (c *Client) CreateToken(ctx context.Context, auth Auth, label string, expires int64) (*Token, error) {
	req := &tokenIssueRequest{Expires: &expires}
	if label != "" {
		req.Label = &label
	}
	var tok Token
	if err := c.do(ctx, auth, http.MethodPost, "/v1/account/token", nil, req, &tok); err != nil {
		return nil, err
	}
	return &tok, nil
}

// DeleteToken calls DELETE /v1/account/token with the X-Token header.
func (c *Client) DeleteToken(ctx context.Context, auth Auth, token string) error {
	if token == "" {
		return errors.New("ntfyapi: empty token")
	}
	return c.do(ctx, auth, http.MethodDelete, "/v1/account/token", http.Header{"X-Token": {token}}, nil, nil)
}

// CreateVerifiedToken creates a token as the user in auth, then checks with
// the new token that ntfy really issued it for wantUser (see ErrWrongUser).
// On a mismatch the token is revoked and ErrWrongUser is returned.
func (c *Client) CreateVerifiedToken(ctx context.Context, auth Auth, wantUser, label string, expires int64) (*Token, error) {
	tok, err := c.CreateToken(ctx, auth, label, expires)
	if err != nil {
		return nil, err
	}
	acc, err := c.Account(ctx, Bearer(tok.Token))
	if err == nil && acc.Username == wantUser {
		return tok, nil
	}
	_ = c.DeleteToken(ctx, Bearer(tok.Token), tok.Token)
	if err != nil {
		return nil, fmt.Errorf("verifying new token: %w", err)
	}
	return nil, fmt.Errorf("%w: wanted %q, got %q", ErrWrongUser, wantUser, acc.Username)
}

// Account calls GET /v1/account as the authenticated user.
func (c *Client) Account(ctx context.Context, auth Auth) (*Account, error) {
	var acc Account
	if err := c.do(ctx, auth, http.MethodGet, "/v1/account", nil, nil, &acc); err != nil {
		return nil, err
	}
	return &acc, nil
}
