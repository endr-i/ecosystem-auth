# ecosystem-auth

Auth + registration microservice in Go. Users register and authenticate with
email + password; a phone number is required at registration for future MFA.
Backed by PostgreSQL.

## Stack

- Go (stdlib `net/http`), pgx/v5, bcrypt password hashing
- JWT (RS256) access tokens with a `kid` header + rotating opaque refresh
  tokens (stored hashed)
- Public keys published at `GET /.well-known/jwks.json` for other services
- Embedded SQL migrations applied automatically on startup
- Redis-backed per-IP rate limiting on auth endpoints (HTTP 429 / gRPC
  `RESOURCE_EXHAUSTED`); fails open if Redis is down
- gRPC API (`proto/auth/v1/auth.proto`) served alongside HTTP; generated code
  committed under `gen/` (contracts will move to a standalone repo later)

## Running

A `Makefile` wraps the common workflows — run `make help` for the full list.

### Default: shared ecosystem infra

Postgres and Redis come from [`ecosystem-infra`](../ecosystem-infra), which
owns the `ecosystem` docker network. Start it first, then:

```sh
make up       # or `make start` — build auth and join the ecosystem network
make logs
make restart  # e.g. after adding a signing key
make down
```

The container is named `ecosystem-auth` and talks to `postgres:5432/auth` and
`redis:6379` inside the network; `make up` fails early with a hint if the
network is missing. Ports 8080/9090 are published to the host.

### Self-contained dev stack

`compose.dev.yaml` still bundles a throwaway Postgres and Redis, for working on
this service without infra running:

```sh
make dev-up
make dev-logs
make dev-down     # dev-reset also drops the db volume
```

It publishes the same host ports as infra, so stop infra first or override
`DEV_POSTGRES_PORT` / `DEV_REDIS_PORT` / `PORT` / `GRPC_PORT`.

### On the host

```sh
make run          # go run against localhost:5432 / localhost:6379
make deps-up      # only if infra is not running: dev postgres + redis
```

Overrides are plain make variables, e.g. `make run PORT=8081`.

`make up`, `make dev-up` and `make run` generate a signing key on first use if
`keys/` is empty; see [Signing keys](#signing-keys).

Or fully by hand against your own Postgres:

```sh
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/auth?sslmode=disable
go run ./cmd/keygen        # writes keys/key-YYYY-MM.pem
go run ./cmd/server
```

### Configuration

| Env var             | Required | Default | Description                          |
| ------------------- | -------- | ------- | ------------------------------------ |
| `DATABASE_URL`      | yes      | —       | Postgres connection string           |
| `JWT_KEYS_DIR`      | no       | `keys`  | Directory of RS256 private keys (PEM) |
| `JWT_ACTIVE_KID`    | no       | newest  | Key id to sign with; defaults to the greatest kid |
| `REDIS_URL`         | no       | `redis://localhost:6379/0` | Redis for rate limiting |
| `PORT`              | no       | `8080`  | HTTP listen port                     |
| `GRPC_PORT`         | no       | `9090`  | gRPC listen port                     |
| `ACCESS_TOKEN_TTL`  | no       | `15m`   | Access token lifetime (Go duration)  |
| `REFRESH_TOKEN_TTL` | no       | `720h`  | Refresh token lifetime (Go duration) |

### Signing keys

Access tokens are signed with **RS256**. Private keys live as PKCS#8 PEM files
in `JWT_KEYS_DIR`; the file name is the key id (`keys/key-2026-09.pem` →
`kid: key-2026-09`). Generate one with:

```sh
make keygen                  # kid defaults to key-YYYY-MM
make keygen KID=key-2026-10  # explicit kid
```

Every key in the directory is trusted for verification, so rotation is: drop in
a new key with a greater kid, restart, and keep the old key around until all
outstanding tokens have expired. Pin a specific signer with `JWT_ACTIVE_KID`.

Keys are gitignored — never commit them. In Docker they are mounted read-only
at `/keys`.

## API

Base path: `/api/v1`

### `GET /.well-known/jwks.json`

Not under the base path. Public keys for other services to verify access
tokens locally. No auth required; cacheable for 5 minutes.

```json
{
  "keys": [
    {
      "kid": "key-2026-09",
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### `POST /api/v1/register`

```json
{ "email": "a@example.com", "password": "password123", "phone": "+15551234567" }
```

Password ≥ 8 chars; phone in E.164 format. Returns `201` with the user, `409`
if the email is taken.

### `POST /api/v1/login`

```json
{ "email": "a@example.com", "password": "password123" }
```

Returns `200` with the user and a token pair:

```json
{
  "user": { "id": "…", "email": "…", "phone": "…", "phone_verified": false, "mfa_enabled": false },
  "tokens": { "access_token": "…", "refresh_token": "…", "token_type": "Bearer", "expires_in": 900 }
}
```

### `POST /api/v1/refresh`

`{ "refresh_token": "…" }` → new token pair. Refresh tokens are single-use
(rotated); the presented token is revoked.

### `POST /api/v1/logout`

`{ "refresh_token": "…" }` → `204`, revokes the refresh token.

### `GET /api/v1/me`

Requires `Authorization: Bearer <access_token>`. Returns the current user.

### `GET /healthz`

Liveness probe.

## Rate limiting

Per client IP, fixed one-minute windows, enforced via Redis on both HTTP and
gRPC:

| Endpoint            | Limit  |
| ------------------- | ------ |
| register            | 5/min  |
| login               | 10/min |
| refresh / logout    | 30/min |

HTTP responses include `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and
`Retry-After` (on 429). gRPC returns `RESOURCE_EXHAUSTED`. If Redis is
unavailable the limiter fails open (requests pass, errors logged).

## gRPC API

`auth.v1.AuthService` (see [`proto/auth/v1/auth.proto`](proto/auth/v1/auth.proto)),
served on `GRPC_PORT` with reflection and the standard health service enabled:

- `Register`, `Login`, `RefreshToken`, `Logout` — mirror the HTTP endpoints
- `ValidateToken` — for other services to verify access tokens
- `GetMe` — fetch the user for an access token

Example with [grpcurl](https://github.com/fullstorydev/grpcurl):

```sh
grpcurl -plaintext -d '{"email":"a@example.com","password":"password123","phone":"+15551234567"}' \
  localhost:9090 auth.v1.AuthService/Register
```

### Regenerating stubs

Requires [buf](https://buf.build), `protoc-gen-go`, and `protoc-gen-go-grpc`:

```sh
make proto     # buf generate
make proto-lint
```

## Tests

```sh
make test      # go test ./...
make check     # fmt + vet + test
```
