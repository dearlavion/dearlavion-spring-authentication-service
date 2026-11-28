# Onboarding a new customer (tenant)

This service is **multi-tenant**: **one running instance serves many customers**. Each customer has
its own isolated user store (`authentication-<customer>` DB), and its JWTs carry a `customer` claim
so a token minted for one customer is **rejected** everywhere else.

The customer is chosen **per request**:
- **credential endpoints** (`register`, `login`, `forgot-password`, `GET/PATCH /auth/user/{username}`,
  `PATCH /auth/me`, and everything under `/admin/users`) read it from the **`X-Customer` header**
  (`/auth/user/{username}` also needs a credential, see the README);
- **`verify`** and **`reset-password`** read it from the **token's `customer` claim** (no header).

Adding a customer is **config, not a new deployment**: add the slug to the `CUSTOMERS` allowlist and
restart. No new port, no new instance.

> Worked example: customer **`travel-besty`**, backed by **`dearlavion-spring-store-engine-v2`** and
> the **`dearlavion-travel-besty-ui`** frontend.

---

## How isolation works (the model)

```
  UI (X-Customer: travel-besty)  ─▶  ┌────────────────────────────────────────────┐
   POST /auth/login                  │  auth-service-v3  (ONE instance)            │
                                     │  CUSTOMERS=travel-besty,acme                │
                                     │  header/claim → MongoTemplate for           │
                                     │                 authentication-<customer>   │
                                     │  JWT: { username, sub, customer, ... }      │
                                     └────────────────────────────────────────────┘
                                          ▲            issues JWT
        Bearer <jwt>                      │ POST /auth/verify   (tenant from the token claim)
            │                             │  → { valid, ..., activeProfile, customer }
            ▼                             │
   ┌──────────────────────────────────────────┐
   │  backend (e.g. store-engine-v2)           │
   │  EXPECTED_CUSTOMER=travel-besty           │
   │  AuthGuard → /auth/verify, then rejects   │
   │  any token whose customer ≠ EXPECTED      │
   └──────────────────────────────────────────┘
```

- One instance, one connection pool. `TenantService` hands out a **`MongoTemplate` per customer**,
  cached in a `ConcurrentHashMap` and bound to that customer's `authentication-<customer>` database
  — deliberately *not* a `MongoRepository`, since the database name isn't known until the request
  arrives. All user CRUD goes through those templates.
- The **`CUSTOMERS` allowlist** rejects unknown/typo slugs (→ 400) so nobody can spawn arbitrary DBs.
- **Admin** is by role: a user's `activeProfile` must be `ADMIN` or `STAFF`. Assigning those roles is
  gated by the `X-Provision-Secret` header (matching the `PROVISION_SECRET` env).

---

## Steps

### 1. Pick a customer id

A short, URL-safe slug — e.g. `travel-besty`. It becomes:

| Thing | Value |
|---|---|
| Entry in `CUSTOMERS` | `travel-besty` |
| Users database | `authentication-travel-besty` |
| `X-Customer` header on auth calls | `travel-besty` |
| JWT `customer` claim | `travel-besty` |
| Backend `EXPECTED_CUSTOMER` | `travel-besty` |

### 2. Add the customer to the auth instance

Append the slug to `CUSTOMERS` (comma-separated) and restart the **existing** instance — no new
process. This service reads plain environment variables (there is no `.env` import), so set them
however you launch it:

```bash
export CUSTOMERS=travel-besty,acme,globex

# One-time per instance: set a strong provisioning secret so you can create admins (below).
# You generate this — the service never issues it.
export PROVISION_SECRET=$(openssl rand -hex 32)

PORT=9081 MONGODB_URI='mongodb+srv://…/authentication?…' mvn spring-boot:run
```

That's the whole server-side change. The DB `authentication-<customer>` is created automatically on
the first `register` (nothing to pre-provision), and `TenantService` builds its unique
username/email indexes the first time the tenant is touched.

### 3. Create the first users (the DB starts empty)

Register against the running instance, **passing `X-Customer`**:

```bash
# a regular user
curl -X POST http://localhost:9081/auth/register \
  -H 'content-type: application/json' -H 'X-Customer: travel-besty' \
  -d '{"username":"traveler","email":"traveler@example.com","password":"secret123"}'

# an admin — pass activeProfile + the provisioning secret (one call, no separate promote)
curl -X POST http://localhost:9081/auth/register \
  -H 'content-type: application/json' -H 'X-Customer: travel-besty' \
  -H 'X-Provision-Secret: <PROVISION_SECRET>' \
  -d '{"username":"owner","email":"owner@example.com","password":"secret123","activeProfile":"ADMIN"}'
```

Roles that grant admin: **`ADMIN`**, **`STAFF`**. `USER` is a regular user (the default). Assigning
`ADMIN`/`STAFF` requires the `X-Provision-Secret` header — without it the user is created/kept `USER`.
The same username/email may exist under a **different** customer — the tenants are fully separate.

Once an admin exists, the rest of that tenant's users can be managed through **`/admin/users`**
(list, create, patch, activate/deactivate, reset password) instead of curl — that group is v3-only,
and the admin UI uses it.

### 4. Point the customer's backend at the shared instance

In the backend (e.g. `dearlavion-spring-store-engine-v2`) environment:

```bash
AUTH_SERVER_URL=http://localhost:9081     # the shared auth instance (same for every customer)
EXPECTED_CUSTOMER=travel-besty            # this backend only accepts travel-besty tokens
```

Its `AuthenticationFilter` verifies each request against `/auth/verify` (which resolves the tenant
from the token claim) and rejects any token whose `customer` ≠ `EXPECTED_CUSTOMER`. Admin routes
additionally require an `ADMIN`/`STAFF` role.

> `AUTH_SERVER_URL` has no safe default — store-engine's falls back to `http://localhost:8081`,
> which is *not* where this service runs. Getting it wrong makes every authenticated call return
> 401, and a frontend that logs out on 401 will bounce users straight back to the login page.

### 5. Point the frontend at both, and tell it its tenant

In the UI (`dearlavion-travel-besty-ui`) `src/environments/environment.dev.ts`:

```ts
export const environment = {
  production: false,
  useMockData: false,
  apiUrl: 'http://localhost:4000',   // the customer's backend
  authUrl: 'http://localhost:9081',  // the shared auth instance
  customer: 'travel-besty',          // sent as X-Customer on every auth call
};
```

`AuthService` attaches `X-Customer: <customer>` to `login()`/`register()`. No other UI change.

---

## Verify it end-to-end

```bash
AUTH=http://localhost:9081 ; API=http://localhost:4000

# login WITH the header → JWT carries { customer: "travel-besty" }
TOK=$(curl -s -X POST $AUTH/auth/login -H 'content-type: application/json' \
  -H 'X-Customer: travel-besty' -d '{"email":"owner@example.com","password":"secret123"}' \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

# verify needs NO header — the tenant comes from the token
curl -s -X POST $AUTH/auth/verify -H 'content-type: application/json' -d "{\"token\":\"$TOK\"}"
#   {"valid":true,...,"activeProfile":"ADMIN","customer":"travel-besty"}

curl -s -o /dev/null -w '%{http_code}\n' $API/admin/products -H "Authorization: Bearer $TOK"   # 200

# guardrails
curl -s -o /dev/null -w '%{http_code}\n' -X POST $AUTH/auth/login \
  -d '{"username":"x","password":"y"}'                                    # 400 (missing X-Customer)
curl -s -o /dev/null -w '%{http_code}\n' -X POST $AUTH/auth/login \
  -H 'X-Customer: unknown' -d '{"username":"x","password":"y"}'           # 400 (not in CUSTOMERS)
# a token from a DIFFERENT customer → verify + backend both 401
```

---

## Environment variable reference

**auth-service-v3 (one shared instance)**

| Var | Example | Purpose |
|---|---|---|
| `CUSTOMERS` | `travel-besty,acme` | Allowlist of tenants this instance serves. Unknown `X-Customer` → 400. Default `dearlavion`. |
| `PROVISION_SECRET` | *(unset)* | Required via `X-Provision-Secret` to assign `ADMIN`/`STAFF` at register/patch. Unset ⇒ privileged roles can't be set via the API. |
| `MONGODB_URI` | `…/authentication?…` | Base connection to the cluster. Every query is routed to `authentication-<customer>`, so the DB in this URI is just the base default. |
| `PORT` | `9081` | HTTP port. **Defaults to `9082`** so v3 can run beside v2 on 9081 — set it explicitly when v3 *is* the instance clients talk to. |
| `JWT_SECRET` | *(unset)* | Base64 HS256 secret; defaults to the shared v1/v2 key so tokens interoperate. Override per environment — the default is in public source. |
| `KAFKA_ENABLED` / `GOOGLE_ENABLED` | `false` | Disable broker / Google OAuth for local dev. Kafka defaults to enabled and will retry a missing broker noisily. |

**consuming backend (per customer)**

| Var | Example | Purpose |
|---|---|---|
| `AUTH_SERVER_URL` | `http://localhost:9081` | The shared auth instance (same value for every customer). |
| `EXPECTED_CUSTOMER` | `travel-besty` | Reject tokens whose `customer` claim differs. Empty disables the check. |
| `ADMIN_USERNAMES` | `admin` | Bootstrap admin escape hatch (role is the primary admin signal). |

**frontend (per customer)**

| Var | Example | Purpose |
|---|---|---|
| `customer` | `travel-besty` | Sent as `X-Customer` on auth calls. |

---

## Notes & gotchas

- **DB creation is automatic** — `authentication-<customer>` is created on the first `register`.
- **Fresh tenants start empty** — users are never shared across customers by design.
- **`EXPECTED_CUSTOMER` must match** the `X-Customer` a UI sends, or that UI's tokens 401 downstream.
- **`PROVISION_SECRET` is operator-generated** (`openssl rand -hex 32`), one per instance — the
  service never issues it. It's a shared operator credential (not per user/tenant): keep it out of
  the frontend/git/logs, source it from your secrets manager in prod, and rotate it if it leaks.
- **Same secret signs all tenants** — isolation rests on the `customer` claim + allowlist, not
  crypto. A per-customer secret map is a later hardening (easy once a `customers` collection exists).
- **Scaling past a handful of customers?** Move the allowlist from `CUSTOMERS` env to a `customers`
  collection for self-serve onboarding (no redeploy) + per-customer settings.
