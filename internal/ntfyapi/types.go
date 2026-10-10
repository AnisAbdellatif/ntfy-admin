// Package ntfyapi is a typed client for the (undocumented, "beta") ntfy admin
// and account HTTP API. It is the only package in ntfy-admin that talks to ntfy.
package ntfyapi

// Roles as returned by GET /v1/users.
const (
	RoleAdmin     = "admin"
	RoleUser      = "user"
	RoleAnonymous = "anonymous"
)

// Everyone is the special username that ntfy uses for anonymous access in ACL calls.
const Everyone = "*"

// Permissions accepted by PUT /v1/users/access and returned in grants.
const (
	PermReadWrite = "read-write"
	PermReadOnly  = "read-only"
	PermWriteOnly = "write-only"
	PermDenyAll   = "deny-all"
)

// Permissions lists all valid permissions, in display order.
var Permissions = []string{PermReadWrite, PermReadOnly, PermWriteOnly, PermDenyAll}

// User is one entry of GET /v1/users.
type User struct {
	Username string  `json:"username"`
	Role     string  `json:"role"`
	Tier     string  `json:"tier,omitempty"`
	Grants   []Grant `json:"grants,omitempty"`
}

// IsAdmin reports whether the user is an admin (read-only via the API).
func (u User) IsAdmin() bool { return u.Role == RoleAdmin }

// IsAnonymous reports whether this is the special anonymous user "*".
func (u User) IsAnonymous() bool { return u.Role == RoleAnonymous || u.Username == Everyone }

// Grant is a single ACL entry. Topic may contain '*' wildcards.
type Grant struct {
	Topic      string `json:"topic"`
	Permission string `json:"permission"`
}

// Token is an access token as returned by POST /v1/account/token and GET /v1/account.
type Token struct {
	Token       string `json:"token"`
	Label       string `json:"label,omitempty"`
	LastAccess  int64  `json:"last_access,omitempty"`
	LastOrigin  string `json:"last_origin,omitempty"`
	Expires     int64  `json:"expires,omitempty"` // unix seconds, 0 = never
	Provisioned bool   `json:"provisioned,omitempty"`
}

// Account is the subset of GET /v1/account that ntfy-admin uses.
type Account struct {
	Username string  `json:"username"`
	Role     string  `json:"role,omitempty"`
	Tokens   []Token `json:"tokens,omitempty"`
}

type userAddRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type userDeleteRequest struct {
	Username string `json:"username"`
}

type accessRequest struct {
	Username   string `json:"username"`
	Topic      string `json:"topic"`
	Permission string `json:"permission,omitempty"`
}

type tokenIssueRequest struct {
	Label   *string `json:"label,omitempty"`
	Expires *int64  `json:"expires,omitempty"`
}

type healthResponse struct {
	Healthy bool `json:"healthy"`
}
