# dearlavion-spring-authentication-service-v3

Spring Boot (Java 21) port of `dearlavion-authentication-service-v2` (NestJS), which was itself a
port of the original Java `dearlavion-authentication-service`. This service is built the same way
that original was — Maven, Spring Boot, `spring-security-crypto`'s `BCryptPasswordEncoder`, the
`jjwt` library — while carrying forward everything v2 added on top: multi-tenancy, the `active`
soft-delete flag, admin user management, and provision-secret-gated role assignment.

The **keystone** service — every other backend verifies bearer tokens against its
`POST /auth/verify`. Runs **alongside** v1 and v2 on a **new port (9082)**, multi-tenant like v2 —
one instance serves many customers, each with its own `authentication-<customer>` MongoDB database.

## Multi-tenancy (per-customer isolation)

One instance serves many customers, allowlisted in `CUSTOMERS`. The tenant is chosen per request —
the `X-Customer` header on credential endpoints, the token's `customer` claim on
`verify`/`reset-password` — and each customer's users live in an isolated
`authentication-<customer>` database, resolved dynamically per request via a `MongoTemplate` built
against that database name (not a fixed `MongoRepository`, which is bound to one database at
startup). Onboard a customer by adding its slug to `CUSTOMERS` and restarting — no new instance, no
code changes; its database and unique username/email indexes are created automatically on first
touch. See **[ONBOARDING-A-CUSTOMER.md](ONBOARDING-A-CUSTOMER.md)** for the step-by-step guide.

## Registering customers, users & admins

Same three-level model as v2: a **customer** (tenant) is config; **users** and **admins** are
created via the API, scoped by the `X-Customer` header.

Roles (`activeProfile`) are `ADMIN`, `STAFF` (both privileged) and `USER` (default). Assigning a
privileged role is gated by the `X-Provision-Secret` header (matching `PROVISION_SECRET`), so the
public signup endpoint can't self-grant admin.

```bash
# Register a regular user (always created as USER regardless of body)
curl -X POST http://localhost:9082/auth/register \
  -H 'Content-Type: application/json' -H 'X-Customer: dearlavion' \
  -d '{"username":"traveler","email":"traveler@example.com","password":"secret123"}'

# Register an admin (needs the provision secret)
curl -X POST http://localhost:9082/auth/register \
  -H 'Content-Type: application/json' -H 'X-Customer: dearlavion' \
  -H 'X-Provision-Secret: <PROVISION_SECRET>' \
  -d '{"username":"owner","email":"owner@example.com","password":"secret123","activeProfile":"ADMIN"}'
```

Without a valid `X-Provision-Secret`, both `register` and `PATCH /auth/user/{username}` silently
force/ignore the role so the user stays `USER`. If `PROVISION_SECRET` is unset, privileged roles
can't be assigned via the API at all (fail closed).

## Token & password interoperability

- **JWT**: HS256, key = the base64-decoded secret, claims `{ username, customer, sub, iat, exp }`,
  24h by default. The secret **defaults to the same key the Java v1 `JwtService` bakes in and the
  NestJS v2 `configuration.ts` falls back to** (`V1_JWT_KEY`), so v1-, v2- and v3-issued tokens
  interoperate out of the box with no configuration — same rule v2 follows. The additive `customer`
  claim is ignored by v1 verification, so tokens still verify on any of the three stacks.
  Override `JWT_SECRET` per environment: this default lives in public source, so anywhere the
  secret actually protects something it must be set explicitly.
- **Passwords**: bcrypt (Spring's `BCryptPasswordEncoder`, strength 10) — hash-compatible with
  bcryptjs (v2) and Spring's own encoder (v1), so passwords verify across all three stacks.
- Same `users` collection shape and field names, one per tenant database.

## Endpoints (`/auth`)

Credential endpoints require the `X-Customer` header; `verify`/`reset-password` read the tenant
from the token instead. An unknown/missing customer on a header-scoped call → 400.

| Method | Path | `X-Customer`? | Notes |
|---|---|---|---|
| POST | `/register?type=SIMPLE&googleToken=` | required | 200 `{message, user}`; 409 if the user exists |
| POST | `/login?type=SIMPLE` | required | 200 `{token, user}`; 401 on bad creds or deactivated account |
| POST | `/verify` | — (from token) | `{token}` → `{valid, username, email, userId, activeProfile, customer}`; 401 `{valid:false}` on any failure |
| GET | `/user/{username}` | required | public user view (no password) |
| PATCH | `/user/{username}` | required | role change requires `X-Provision-Secret` |
| POST | `/forgot-password?email=` | required | always 200; silent no-op if the email is unknown |
| POST | `/reset-password` | — (from token) | `{token, newPassword}` → 200 |
| POST | `/verify-google` | — | `{idToken}` → `{email}` |

## Cookie sessions, profile & lookup (for browser apps such as Dear Creative)

Additive: `POST /auth/login` and its 24h token are unchanged. These endpoints give a browser app a short
access token plus a rotating refresh token in an httpOnly, SameSite=Strict cookie. The tenant comes from
`X-Customer`, as on the other credential endpoints.

| Method | Path | Notes |
|---|---|---|
| POST | `/auth/session/login` | `{username or email, password}` → `{token, expiresIn, user}` + refresh cookie |
| POST | `/auth/session/refresh` | needs the cookie; rotates it (the old one stops working) and returns a new `{token, ...}` |
| POST | `/auth/session/logout` | revokes the cookie's token, clears the cookie (204) |
| GET | `/auth/me` | Bearer → the caller's own profile (`id, username, email, firstname, lastname, bio, image, activeProfile, customer`) |
| PATCH | `/auth/me/profile` | Bearer; `{firstname?, lastname?, bio?}`, null leaves a field alone, `""` clears the bio |
| POST | `/auth/me/verify-password` | Bearer; `{password}` → `{valid}`, for a backend to re-check the caller before a destructive action |
| POST | `/auth/internal/users/lookup` | service-to-service: `X-Service-Key` + `X-Customer`; `{ids?:[…], usernames?:[…]}` (max 200 in all) → `[{id, username, email, firstname, lastname, bio}]`, only that tenant. Not a user token, since some callers serve visitors who aren't logged in. Always 401 while `SERVICE_KEY` is unset. |

- Access tokens carry the user's id in a `uid` claim (also added to `/auth/login` tokens; v1/v2 verification ignores it).
  The Bearer endpoints above require `uid` and re-check that the user still exists and is active, which also stops a
  password-reset token (same key, no `uid`) from being used as a login.
- Refresh tokens are stored hashed in each tenant's own `refresh_tokens` collection, with a TTL index.
- `POST /auth/register` still ignores `firstname`/`lastname` (existing behaviour); set the display name afterwards
  with `PATCH /auth/me/profile`.
- Usernames and emails are stored as given, so a client that wants case-insensitive accounts must lower-case them.
- Verifying these tokens elsewhere: HS256 with the base64-decoded `JWT_SECRET`, claims `sub`/`username` (username),
  `customer`, `uid`. A backend that verifies locally will not notice a deactivated user until the access token
  expires (15 min by default); `POST /auth/verify` checks the user on every call.

## Admin user management (`/admin/users`)

Guarded locally (no HTTP round-trip to itself): decode the Bearer JWT, resolve the tenant from its
own signed `customer` claim (never a client header), require `activeProfile` ∈ `{ADMIN, STAFF}`.
No token → 401; bad/expired token → 401; wrong role → 403.

`GET /admin/users`, `GET /admin/users/{username}`, `POST /admin/users`,
`PATCH /admin/users/{username}`, `PATCH /admin/users/{username}/active`,
`PATCH /admin/users/{username}/password`.

## Admin approval, permissions & superadmin (`/superadmin`)

Powers `dearlavion-security-ui`. Superadmins live in a dedicated **security tenant** (`SECURITY_TENANT`, default
`security`, which must also be in `CUSTOMERS`) and are the only accounts that can act across projects.

- `POST /auth/admin-request` (`X-Customer`; `{username, email, password}`) creates an ADMIN with status `PENDING`. It can't
  sign in (login, refresh, `/auth/verify`, `/admin/**` all refuse it) until a superadmin approves it.
- Approval sets `status` (`PENDING|APPROVED|REJECTED`) and, when approving, `permission` (`READ|MODIFY|BOTH`). `/admin/**`
  enforces it: `READ` allows GET only, `MODIFY` writes only, `BOTH` everything. Accounts that predate this have no status or
  permission and count as `APPROVED` / `BOTH`, so nothing existing is locked out.
- `POST /auth/verify` now also returns `permission`; consuming backends should enforce it (it is the source of truth, the
  JWT doesn't carry it, so a revoke takes effect on the next verify).
- `/admin/users` no longer lets a project admin set roles: creating ignores the body's `activeProfile` (always `USER`) and
  updating can't change it. Handing out ADMIN/STAFF is a superadmin decision. `SUPERADMIN` can only be created in the
  security tenant (register with `X-Provision-Secret`).
- `/superadmin/*` (Bearer token of a SUPERADMIN in the security tenant): `GET /projects`, `GET /projects/{customer}/users`
  (`role=ADMIN|USER`, `status`, `q`, `page`, `size`), `PATCH /projects/{customer}/users/{username}/approval`
  (`{status, permission}`), `PATCH .../active`, `GET /approvals`, `GET /audit`. Decisions are logged to `audit_log` in the
  security tenant's database.

First superadmin: add `security` to `CUSTOMERS`, then
`POST /auth/register` with `X-Customer: security`, `X-Provision-Secret`, and `"activeProfile":"SUPERADMIN"`.

## Events (Kafka)

Topic `authentication-service-event`, `{ type, payload }` envelope — `NEW_USER` on register,
`RESET_PASSWORD` on forgot-password, matching v1/v2 so `notification-service` consumes them
unchanged. Set `KAFKA_ENABLED=false` to no-op publishing (e.g. for local dev without a broker).

## Commands

```bash
mvn compile
mvn test              # Testcontainers integration tests (needs Docker, Kafka disabled for the run)
mvn spring-boot:run    # dev server on :9082
```

## Configuration (env vars)

| Var | Default |
|---|---|
| `PORT` | 9082 |
| `CUSTOMERS` | `dearlavion` — comma-separated tenant allowlist |
| `PROVISION_SECRET` | *(empty)* — operator-generated (`openssl rand -hex 32`); required via `X-Provision-Secret` to assign `ADMIN`/`STAFF` |
| `MONGODB_URI` | `mongodb://localhost:27017/authentication-service` — base connection; per-tenant databases are `authentication-<customer>` |
| `JWT_SECRET` | the v1/v2 base64 key — interoperates out of the box; override per environment (the default is in public source) |
| `JWT_EXPIRES_IN_SECONDS` / `JWT_RESET_EXPIRES_IN_SECONDS` | 86400 (24h) / 900 (15m) |
| `KAFKA_ENABLED` / `KAFKA_BROKERS` / `KAFKA_CLIENT_ID` | true / `localhost:29092` / `dearlavion-spring-authentication-service-v3` |
| `GOOGLE_ENABLED` / `GOOGLE_CLIENT_ID` | true / *(empty)* |
| `SERVICE_KEY` | *(empty)* — shared secret for `/auth/internal/*`; generate with `openssl rand -hex 32` |
| `SESSION_ACCESS_TTL_SECONDS` / `SESSION_REFRESH_TTL_DAYS` | 900 (15m) / 14 |
| `SESSION_COOKIE_NAME` / `SESSION_COOKIE_PATH` / `SESSION_COOKIE_SECURE` | `dl_refresh` / `/auth` / `false`; the path must be the one the browser sees (e.g. `/api/v1/auth` behind a proxy), and `SESSION_COOKIE_SECURE=true` over https |
| `SECURITY_TENANT` | `security` — tenant holding SUPERADMIN accounts; must also be listed in `CUSTOMERS` |
| `FRONTEND_ORIGINS` | *(empty)* — extra CORS origins beyond the built-in dearlavion.site/localhost:4200/ngrok.pizza list |

Health at `/actuator/health` (matches v1's path), Swagger at `/swagger-ui/index.html`.

## Verification performed

7 Testcontainers integration tests: register/login/verify round trip, multi-tenant isolation (same
username under different customers resolves to different accounts and different passwords), unknown
customer rejection, provision-secret role gating, the admin-guard's exact 401 (no/bad token) vs 403
(wrong role) distinction, and soft-delete blocking login. Plus a live curl smoke test against a real
MongoDB instance.
