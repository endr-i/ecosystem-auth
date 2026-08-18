# ecosystem-auth

Auth + registration microservice in Go. Users register and authenticate with
email + password; a phone number is required at registration for future MFA.
Backed by PostgreSQL.

## Stack

- Go (stdlib `net/http`), pgx/v5, bcrypt password hashing
- JWT (HS256) access tokens + rotating opaque refresh tokens (stored hashed)
- Embedded SQL migrations applied automatically on startup
- gRPC API (`proto/auth/v1/auth.proto`) served alongside HTTP; generated code
  committed under `gen/` (contracts will move to a standalone repo later)

## Running

```sh
docker compose up --build
```

Or locally against your own Postgres:

```sh
export DATABASE_URL=postgres://auth:auth@localhost:5432/auth?sslmode=disable
export JWT_SECRET=your-secret
go run ./cmd/server
```

### Configuration

| Env var             | Required | Default | Description                          |
| ------------------- | -------- | ------- | ------------------------------------ |
| `DATABASE_URL`      | yes      | —       | Postgres connection string           |
| `JWT_SECRET`        | yes      | —       | HMAC secret for access tokens        |
| `PORT`              | no       | `8080`  | HTTP listen port                     |
| `GRPC_PORT`         | no       | `9090`  | gRPC listen port                     |
| `ACCESS_TOKEN_TTL`  | no       | `15m`   | Access token lifetime (Go duration)  |
| `REFRESH_TOKEN_TTL` | no       | `720h`  | Refresh token lifetime (Go duration) |

## API

Base path: `/api/v1`

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
buf generate
```

## Tests

```sh
go test ./...
```
