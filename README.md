# ntfy-admin

A small self-hosted web UI for administering a self-hosted [ntfy](https://ntfy.sh) server:
users, per-topic access control, and token-only service accounts.

It runs next to your ntfy container and talks to ntfy **only through ntfy's HTTP API**.
There is no CLI wrapping, no direct database access, no database of its own, and no
separate credential store: you log in with an ntfy admin account.

**Tested ntfy version: v2.29.0** (see [Testing](#testing)).

## Features

- **Users**: list, add (with initial rules), delete, change password. Admin users are
  shown read-only.
- **Access control**: grant or revoke `read-write`, `read-only`, `write-only` or
  `deny-all` per topic or topic pattern (`backup_*`), for users and for anonymous (`*`).
  "Revoke all rules" requires typing the username.
- **Topics view**: a topic-centric view derived from the ACL. It shows who can do what on
  each topic or pattern, and which patterns also match an exact topic. It has quick
  actions ("make public read-only", "make private") and a users × topics matrix.
- **Service accounts**: dedicated users (named `svc-…`) for scripts and devices. You can
  issue tokens (shown once, with copy-ready `curl` examples), list them masked, revoke
  them, disable the account or delete it.

## How it works

- **Login.** ntfy-admin creates a short-lived ntfy token with your admin credentials
  (`POST /v1/account/token`). It then checks admin rights with `GET /v1/users`. The token
  is kept server-side in an in-memory session; the browser only gets a random session
  cookie. Your password is never stored.
- **Logout and expiry.** Logging out, session expiry and a graceful shutdown all revoke
  the ntfy token. ntfy keeps at most 60 tokens per user and prunes the oldest, so
  ntfy-admin keeps session tokens short-lived (`SESSION_TTL`).
- **No caching.** Every page re-reads state from ntfy, and every change is followed by a
  redirect and a fresh read.
- **Service accounts.** ntfy has no admin API for other users' tokens, so ntfy-admin
  manages them as the service user itself:
  1. It sets a fresh random password (`PUT /v1/users`). Existing tokens stay valid.
  2. It uses that password once for the account's token endpoints.
  3. It discards the password.

  A service account only ever authenticates with tokens, so this is safe. Full token
  values never appear in the HTML except once, right after issuing.

## Requirements in ntfy

Your ntfy `server.yml` needs authentication enabled and at least one admin:

```yaml
auth-file: "/var/lib/ntfy/user.db"
auth-default-access: "deny-all"        # recommended
auth-users:
  - "admin:$2a$10$...:admin"           # create the hash with: ntfy user hash
```

You can also create the admin with the CLI (`ntfy user add --role=admin admin`).

ntfy-admin must be able to reach ntfy over the network (e.g. `http://ntfy:80` on a shared
Docker network). No shared volumes are needed.

**Rate limits.** All of ntfy-admin's requests come from one IP, as seen by ntfy. If you
manage many users at once and hit ntfy's visitor limits, exempt ntfy-admin's address in
ntfy:

```yaml
visitor-request-limit-exempt-hosts: "ntfy-admin"   # container name, IP or CIDR
```

## Quick start (Docker Compose)

Images are published to GitHub Container Registry for `linux/amd64`, `linux/arm64` and
`linux/arm/v7`:

- `ghcr.io/anisabdellatif/ntfy-admin:latest`: latest release (`v*` tag)
- `ghcr.io/anisabdellatif/ntfy-admin:1.2.3`, `:1.2`: specific releases
- `ghcr.io/anisabdellatif/ntfy-admin:edge`: latest commit on `main`

See [`docker-compose.example.yml`](docker-compose.example.yml):

```yaml
services:
  ntfy-admin:
    image: ghcr.io/anisabdellatif/ntfy-admin:latest
    environment:
      NTFY_URL: "http://ntfy:80"
      NTFY_PUBLIC_URL: "https://ntfy.example.com"
    ports:
      - "127.0.0.1:8080:8080"
```

Put it behind your HTTPS reverse proxy. Cookies are `Secure` by default, so plain HTTP
only works with `COOKIE_SECURE=false` (local testing only).

The image is distroless, runs as non-root, and has a built-in healthcheck
(`/ntfy-admin healthcheck`, which calls `GET /healthz`). `GET /healthz?ntfy=1` also checks
ntfy's `/v1/health`.

## Configuration

Set these environment variables. Each has an equivalent flag, e.g. `-ntfy-url`; run
`ntfy-admin -h` to list them.

| Variable | Default | Description |
|---|---|---|
| `NTFY_URL` | — (required) | Base URL ntfy-admin uses to reach ntfy, e.g. `http://ntfy:80`. |
| `NTFY_PUBLIC_URL` | `NTFY_URL` | Public ntfy URL, used in the `curl` examples shown with new tokens. |
| `LISTEN` | `:8080` | Listen address. |
| `COOKIE_SECURE` | `true` | `Secure` flag on cookies. Set to `false` only for plain-HTTP testing. |
| `SESSION_TTL` | `12h` | Session lifetime, and lifetime of its ntfy token (plus 5 min grace). Minimum `5m`. |
| `SVC_PREFIX` | `svc-` | Username prefix that marks service accounts. |
| `TRUSTED_PROXIES` | — | Comma-separated IPs/CIDRs of reverse proxies whose `X-Forwarded-For` is honoured. |
| `BASE_PATH` | — | Path prefix when served under a subpath, e.g. `/admin`. |

**Logging.** Operational logs go to stderr. One JSON audit line per mutation goes to
stdout, with these fields: `time`, `actor`, `ip`, `action`, `target` and `result`.
Passwords are never logged, and tokens are only logged masked (`tk_abcd…wxyz`).

## Security

- The ntfy token stays server-side. The session cookie is `HttpOnly`, `Secure` and
  `SameSite=Strict`.
- Every state-changing request needs a CSRF token, including login (double-submit
  cookie).
- Strict CSP with no inline scripts or styles, plus `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer` and `X-Content-Type-Options: nosniff`.
- Login rate limit: 5 failures per IP per 15 minutes. Failed logins take at least 1 s to
  answer.
- `X-Forwarded-For` is only honoured from `TRUSTED_PROXIES`.
- All input is validated with ntfy's own rules before any call to ntfy.

Sessions live in memory, so restarting ntfy-admin logs everyone out. A graceful shutdown
revokes all session tokens. After a crash, the tokens expire on their own.

## Limitations

ntfy's admin API does not offer the following, so ntfy-admin cannot do them:

- Creating admins, changing roles, or modifying or deleting admin users. Use
  `server.yml` `auth-users` or the ntfy CLI.
- Changing default access. `auth-default-access` lives in `server.yml`.
- Listing topics that exist or are active. The topics view is derived from the ACL only.
- Tiers, reservations, message purging and stats.
- Listing all tokens of all users, or per-token permissions. An ntfy token always has the
  full access of its user, which is why ntfy-admin uses one service account per script or
  device.

Other behaviour to know about:

- **Config-defined entries.** ntfy re-applies users, ACL entries and tokens from
  `server.yml` (`auth-users`, `auth-access`, `auth-tokens`) at startup. Changes made here
  to those entries may be reverted on the next restart. Tokens from `auth-tokens` are
  shown as "from server.yml" and cannot be revoked here.
- **Password changes.** Changing a password does not invalidate the user's existing
  tokens.
- **Disabling a service account.** "Disable" revokes all of the account's rules. Its
  tokens then only get `auth-default-access`. Use `deny-all` as the default for this to
  mean "no access".

The admin API is officially undocumented ("beta" since ntfy v2.5.0). The integration test
guards the contract.

## Development

ntfy-admin is a single Go binary that uses only the standard library.

```
cmd/ntfy-admin/      entrypoint, config, healthcheck subcommand
internal/ntfyapi/    typed ntfy API client (the only package that talks to ntfy)
internal/ntfyfake/   in-memory fake of the ntfy API for unit tests
internal/session/    in-memory session store
internal/web/        handlers, templates and static assets (embedded)
integration/         pinned ntfy (docker compose) for the integration test
```

```sh
make test          # unit tests against the in-memory fake
make integration   # starts the pinned ntfy, runs the integration test, tears it down
make docker        # builds ntfy-admin:latest
```

### Releasing

[`.github/workflows/release.yml`](.github/workflows/release.yml) runs the unit tests, then
builds and pushes the multi-arch image to `ghcr.io/<owner>/ntfy-admin`. Pushes to `main`
publish `:edge`. A tag such as `v1.0.0` publishes `:1.0.0`, `:1.0` and `:latest`:

```sh
git tag v1.0.0 && git push origin v1.0.0
```

New GHCR packages are private. To allow anonymous pulls, make the package public once in
its GitHub package settings.

### Testing

- **Unit tests** run against `internal/ntfyfake`, an `httptest` fake of the ntfy
  endpoints. They cover the error shapes and the 401, 403 and 409 paths.
- **The integration test** (`-tags integration`) runs against a real, pinned
  `binwiederhier/ntfy` from `integration/docker-compose.yml`, which uses `auth-file`,
  `auth-default-access: deny-all` and an admin from `auth-users`. It covers:
  - login, including rejection of non-admins and wrong passwords;
  - adding and deleting users, and changing passwords;
  - granting and revoking access, including anonymous `*`;
  - creating a service account, and issuing, listing and revoking its tokens;
  - publishing with a token, which must succeed before revoke and fail after;
  - session token cleanup on logout.

  CI runs it. **Run it whenever you bump the ntfy version**, then update the image tag in
  `integration/docker-compose.yml` and the tested version at the top of this README.

## Possible upstream follow-ups

Small additions to ntfy (`server/server_admin.go`) would remove the workarounds:

- An admin-only `GET /v1/topics` listing active topics with subscriber counts.
- Admin endpoints for any user's tokens (list, create, delete), wrapping the existing
  `user.Manager` methods `Tokens`, `CreateToken` and `RemoveToken`.
