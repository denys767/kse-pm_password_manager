# Security concerns for real deployment

This document tracks security-relevant design decisions and open risks that
matter once this app leaves a developer's laptop. It complements
`docs/DEPLOYMENT.md` (setup steps) and `docs/OPERATIONS.md` (runbooks) —
those describe *how* to deploy; this describes *what could go wrong* and why.

## 1. Google Workspace directory credentials — key vs. impersonation

`GoogleWorkspaceDirectoryClient` originally authenticated with a static
downloaded JSON key delegated to a Workspace admin. That was replaced in
2026-07 with keyless impersonation: load the caller's Application Default
Credentials, call IAM Credentials `signJwt` as that caller to sign a
domain-wide-delegation assertion, exchange it for a short-lived Directory
token. On GCP, where ADC is an attached service account, that remains the
best option — nothing is on disk, the caller credential is scoped to
`iam.serviceAccounts.signJwt` on one service account, and it is revocable by
removing an IAM binding.

Off GCP that design has no safe form on its own. The only ADC available there
is a `gcloud auth application-default login` user credential, and Google's
reauth policy expires it within hours (`invalid_grant / invalid_rapt`) —
directory suggestions, group sync and new shares stop working until a human
logs in again. A password manager cannot be built on a credential that needs a
human overnight. 2026-07 added workload identity federation to close that gap
without a downloaded key: the app authenticates to this stack's own Keycloak
with a `client_credentials` machine grant (no human, nothing a reauth policy
can touch) and exchanges that OIDC token at Google STS for the caller identity
that signs the delegation assertion.

So three modes are supported and the deployment picks (see
`docs/DEPLOYMENT.md`):
- **Mode B, attached service account** — preferred wherever it exists; keyless.
- **Mode A, workload identity federation** — the recommended choice off GCP;
  keyless, self-renewing, and needs no Workspace-admin-authorized private key.
  Its own secret is a Keycloak client secret (`WORKSPACE_FEDERATION_CLIENT_SECRET`),
  which is local infrastructure we mint and rotate ourselves — not a Google
  credential — and grants nothing on its own without the matching GCP IAM
  binding on the workload identity pool.
- **Mode C, service-account key** (`GOOGLE_WORKSPACE_CREDENTIALS_PATH`) — last
  resort, with the original risk back: a standing, unexpiring,
  domain-wide-readable secret. Mitigate it — mount read-only from a secret
  store, never bake it into an image or git, restrict to the three
  `admin.directory.*.readonly` scopes plus `drive.appdata`, rotate by
  replacing the file (picked up without a restart), and watch for the managed
  org policy `iam.managed.disableServiceAccountKeyCreation`, which blocks key
  creation in newer Google orgs.

What must not change:
- Restrict DWD scopes to exactly the three Directory read-only scopes plus
  `drive.appdata`; never grant write/admin scopes.
- Credential problems fail closed *for Directory data*: `DelegatedTokenMinter.mint()`
  throws 502 and, with no service account configured at all,
  `UnavailableWorkspaceDirectoryClient` takes over. Interactive lookups then
  degrade to the local Workspace snapshot (§5) rather than inventing data, and
  the synchronizer never treats that snapshot as a fresh Directory read.
- The application reports its credential mode at startup and on the Admin tab
  (`credentialUnattended`); a deployment running on a user credential is
  visibly misconfigured rather than quietly doomed.

## 2. Rate limiting trusted a spoofable client IP — fixed 2026-07-23

`RateLimitFilter` (`src/main/java/.../auth/RateLimitFilter.java:59-65`)
keys its per-minute window on the **first** value in `X-Forwarded-For`.
`nginx/nginx.conf` used to set this header with
`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`, which
*appends* nginx's view of the real client IP to whatever the client already
sent instead of replacing it. A request arriving as
`X-Forwarded-For: 1.2.3.4` became `X-Forwarded-For: 1.2.3.4, <real-ip>` at
the app, and the filter read `1.2.3.4` (attacker-controlled) as the
rate-limit key — trivially bypassable by sending a different fake first
value on every request, defeating brute-force throttling on
login-adjacent and external-share endpoints.

**Fix applied:** both server blocks in `nginx/nginx.conf` now set
`proxy_set_header X-Forwarded-For $remote_addr;` (overwrite, not append).
This is correct specifically because nginx is the *only* hop before the
app/Keycloak in this deployment — if a second proxy/CDN (e.g. Cloudflare)
is ever added in front of nginx, revisit this: it would need to trust that
upstream's `X-Forwarded-For` instead of blindly overwriting with
`$remote_addr` (which would then be the CDN's IP, not the real client's).

Also note in `RateLimitFilter`'s own comment: the limiter is in-memory and
per-node — it resets on restart and does not coordinate across replicas.
Fine for the current single-node deployment; revisit (e.g. bucket4j +
Redis) before horizontal scaling.

## 3. Passkey is registration-only, not enforced 2FA on every login

Per `docs/KEYCLOAK.md` ("Спроба зробити passkey 2FA на кожному вході —
відкочена"), an attempt to require WebAuthn on every login (not just
first-time registration) via `postBrokerLoginFlowAlias` broke new-account
creation and was reverted. Current state: passkey registration is a
required action after the *first* successful Google SSO login, but it is
**not re-checked on subsequent logins** — a stolen/replayed Google SSO
session is sufficient on its own for repeat access; the passkey is not a
standing second factor. Anyone deploying this expecting WebAuthn to be a
real MFA gate should know it currently is not, and should track the
"custom Keycloak SPI/authenticator" direction noted in `KEYCLOAK.md` before
claiming MFA coverage in a compliance/audit context.

## 4. No server-side recovery of vault key material

The KMS recovery escrow that used to wrap every item, collection and passkey
key for a service identity was removed: no component of the deployment can
decrypt a user's records without that user's vault passphrase. A user who
forgets the passphrase resets the vault (`POST /api/vault/reset`), which
destroys their owned records after ownership of anything shared has been
transferred to a successor who already holds an encrypted copy of the key.
Two consequences to keep in mind:
- There is no administrator "break glass" path to a departed employee's
  personal records. Anything that must survive an offboarding has to be
  shared with a collection or a second user *before* it is needed.
- Reintroducing escrow would change the trust model back — it is a
  security-property change, not an ops feature, and belongs in this document
  rather than only in a deployment runbook.

## 5. `hostedDomain` is a UI/login-flow hint, not the real authorization boundary

`keycloak/realm-export.json`'s Google identity provider sets `hostedDomain`
to restrict the Google account picker to the org's domain. This is
**defense in depth, not the actual gate**: the real authorization boundary
is `GovernedAuthenticationFilter`, which requires an email to exist as a
`WorkspaceUser` synced from the Directory API for the configured
`GOOGLE_WORKSPACE_DOMAIN` — anyone who reaches Keycloak's first-broker-login
without a matching Workspace record still gets a Keycloak user record
created (`syncMode: IMPORT`) but is denied at the API layer (403 "Workspace
account is not provisioned"). Two consequences to keep in mind:
- If `hostedDomain` is ever cleared or misconfigured, Keycloak will still
  create local user records for out-of-domain Google accounts even though
  they can never call the API — mostly a data-hygiene/cleanup concern, not
  an access-control break, but worth periodic review of orphaned Keycloak
  users.
- Do not treat `hostedDomain` alone as sufficient access control if the
  Directory sync (`GOOGLE_WORKSPACE_DOMAIN`) and `hostedDomain` are ever
  set to different values — they must match, or the two layers disagree
  about who's "internal."

There is one deliberate exception to "the snapshot is the boundary". While
the local Workspace snapshot is **empty** — it has never been fetched, because
the database is new, the caller's credentials expired, or Directory is down —
`GovernedAuthenticationFilter` admits an in-domain, SSO-authenticated account
as an ordinary `USER` instead of denying every request. Without it, one
expired credential locks every user out of their own vault. What this costs
and why it is bounded:
- It applies only when there are **zero** `WorkspaceUser` rows. One successful
  sync ends it permanently for that database; an unknown or revoked account is
  refused again as soon as there is any data to judge it by.
- It never grants `ADMIN`, so admin screens and workspace governance stay shut.
- Google is still the live authority during login (a suspended Google account
  cannot complete SSO at all), and Keycloak still enforces `hostedDomain`.
- It is logged (`WARN`, at most once a minute) and visible on the Admin tab
  through `GET /api/admin/workspace/directory-status`.
- `WORKSPACE_PROVISIONAL_ACCESS=false` turns it off for deployments that
  prefer a hard outage to a degraded boundary.

## 6. Secrets inventory — all of these must leave `.env`/git before production

| Secret | Used for | Notes |
|---|---|---|
| `GOOGLE_CLIENT_SECRET` | Keycloak Google IdP token exchange | Rejects login silently as a generic Keycloak error page if wrong/missing — easy to misdiagnose |
| `WORKSPACE_FEDERATION_CLIENT_SECRET` | Keycloak `client_credentials` grant for workload identity federation | Local secret, not a Google credential; grants nothing without the matching GCP IAM binding. The recommended way to run unattended off GCP without a downloaded key (see `DEPLOYMENT.md`) |
| `GOOGLE_WORKSPACE_CREDENTIALS_PATH` (JSON key) | Directory API + Drive attachments, domain-wide delegation | Last-resort credential when federation and an attached service account are both unavailable (see `DEPLOYMENT.md`). Mount read-only, never bake into an image, rotate by replacing the file |
| `KEYCLOAK_EVENTS_SECRET` | Shared secret for `/api/audit/keycloak-events` | `nginx/nginx.conf:29` explicitly 404s this path on the public edge — keep that rule if the proxy config is ever regenerated |
| `DB_PASSWORD`, `KEYCLOAK_ADMIN_PASSWORD` | Postgres / Keycloak bootstrap admin | Standard, but note `KEYCLOAK_ADMIN_PASSWORD` is a full Keycloak realm admin — treat as tier-0 |

None of these should be baked into a container image or committed; `.env`
is gitignored but still lives in plaintext on disk — a secret manager
(GCP Secret Manager, Vault, etc.) is the real target for a production
deployment, not a long-lived `.env` file on the host.

## 7. Login/logout audit events have no built-in delivery path

Per `docs/KEYCLOAK.md` ("Login/logout audit events: потрібен provider"),
the standard `quay.io/keycloak/keycloak:26.0` image has no ready-made HTTP
event listener — LOGIN/LOGIN_ERROR/LOGOUT events are not forwarded to
`/api/audit/keycloak-events` without deploying a custom `EventListenerProvider`
SPI JAR, which is not currently installed. Until that SPI exists and is
verified against a real Keycloak instance, do not assume login-failure
anomaly detection (`GET /api/audit/anomalies`) sees Keycloak-side failures
— it only sees whatever actually reaches that endpoint.

## 8. Everything else already enforced correctly (verify, don't re-litigate)

Listed so a future security review doesn't waste time re-discovering
these — checked while writing this doc:
- `/actuator/*` is blocked at the nginx edge except `/actuator/health`
  (`nginx/nginx.conf:18-22`); Swagger UI is also blocked publicly.
- CSRF is disabled deliberately because the API is a stateless bearer-token
  resource server with no cookie-based session (`SecurityConfig.java`) —
  re-enable it if cookie auth is ever introduced.
- CSP/HSTS/`X-Frame-Options: DENY`/`nosniff` are set at the nginx layer
  (`nginx/nginx.conf:9-13`).
- The Keycloak audit-events endpoint is 404'd on the public edge
  (`nginx/nginx.conf:27-30`) so the shared secret can only be presented
  over the internal Docker network.
