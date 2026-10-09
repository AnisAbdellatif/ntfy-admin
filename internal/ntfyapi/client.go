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

// Client talks to one ntfy server.
type Client struct {
	baseURL string
	http    *http.Client
}

// New creates a client for the ntfy server at baseURL (e.g. "http://ntfy:80").
func New(baseURL string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient}
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
func (c *Client) AddUser(ctx context.Context, auth Auth, username, password, tier string) error {
	return c.do(ctx, auth, http.MethodPost, "/v1/users", nil, &userAddRequest{Username: username, Password: password, Tier: tier}, nil)
}

// UpdateUser calls PUT /v1/users. Careful: ntfy creates the user if it does not exist.
func (c *Client) UpdateUser(ctx context.Context, auth Auth, username, password, tier string) error {
	return c.do(ctx, auth, http.MethodPut, "/v1/users", nil, &userAddRequest{Username: username, Password: password, Tier: tier}, nil)
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

// Account calls GET /v1/account as the authenticated user.
func (c *Client) Account(ctx context.Context, auth Auth) (*Account, error) {
	var acc Account
	if err := c.do(ctx, auth, http.MethodGet, "/v1/account", nil, nil, &acc); err != nil {
		return nil, err
	}
	return &acc, nil
}
