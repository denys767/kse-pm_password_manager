# Security concerns for real deployment

This document tracks security-relevant design decisions and open risks that
matter once this app leaves a developer's laptop. It complements
`docs/DEPLOYMENT.md` (setup steps) and `docs/OPERATIONS.md` (runbooks) —
those describe *how* to deploy; this describes *what could go wrong* and why.

## 1. Google Workspace directory access — keyless impersonation, fixed 2026-07-23

`GoogleWorkspaceDirectoryClient` used to authenticate with a static
downloaded JSON key (`ServiceAccountCredentials.fromStream(credentialsPath)`)
delegated to a Workspace admin for domain-wide delegation (DWD) — the
weakest link in the whole design: no expiry, domain-wide blast radius on
leak (`admin.directory.*.readonly` for every user in the domain), and
exactly the pattern newer Google orgs block by default via the managed org
policy `iam.managed.disableServiceAccountKeyCreation`.

**Fix applied:** `GoogleWorkspaceDirectoryClient` (`src/main/java/.../directory/GoogleWorkspaceDirectoryClient.java`)
no longer loads any key file. It now:
1. Loads the *caller's* Application Default Credentials (ADC) — on GCP
   compute this is the attached service account via the metadata server; for
   local testing it's `gcloud auth application-default login`.
2. Calls the IAM Credentials API (`iamcredentials.googleapis.com:signJwt`)
   as that caller to sign a DWD JWT assertion (`iss`=target service account,
   `sub`=`GOOGLE_WORKSPACE_ADMIN_EMAIL`, the three Directory scopes), which
   only requires the caller to hold `roles/iam.serviceAccountTokenCreator`
   on the target service account — no key material ever leaves Google's
   servers.
3. Exchanges the signed JWT at `oauth2.googleapis.com/token`
   (`urn:ietf:params:oauth:grant-type:jwt-bearer`) for a normal delegated
   access token, cached in memory until near-expiry (`directoryToken()`).

This changes the property of a leak: what can now leak is, at most, a
caller credential scoped to `iam.serviceAccounts.signJwt` on one specific
service account — revocable by removing an IAM binding or (for the local
`gcloud` case) revoking the user's OAuth grant — rather than a standing,
unexpiring, domain-wide-readable bearer secret. Domain-wide delegation
authorization in the Workspace Admin Console (client ID → the three
`admin.directory.*.readonly` scopes) is unchanged; only how the app proves
it's allowed to ask for that delegation changed.

Still true and worth keeping:
- Restrict DWD scopes to exactly the three Directory read-only scopes
  (plus `drive.appdata` for recovery); never grant write/admin scopes.
- If ADC/impersonation is missing or the target lacks
  `roles/iam.serviceAccountTokenCreator`, the app fails closed —
  `mintDelegatedToken()` throws `BadGatewayException` (502), and if
  `GOOGLE_WORKSPACE_SERVICE_ACCOUNT_EMAIL` isn't set at all,
  `UnavailableWorkspaceDirectoryClient` takes over and throws 502 rather
  than silently skipping governance. Keep that fail-closed behavior in any
  further refactor.

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

## 4. Recovery escrow breaks zero-knowledge, by design

Documented in `docs/DEPLOYMENT.md` ("Recovery escrow and KMS runbook") —
repeating here because it's a security *property change*, not just an ops
step: any item/collection/passkey enrolled in recovery wrapping can be
decrypted server-side by an authorized administrator via Cloud KMS. This
is an intentional trade-off (lost-key recovery), but it means the
deployment is **not** zero-knowledge for recovery-wrapped records. Anyone
evaluating this app's threat model (e.g. for a security review) needs that
called out explicitly, not discovered by reading KMS IAM bindings later.
Controls that make this acceptable — step-up SSO for recovery operators,
mandatory case/ticket reason, audit trail, never logging plaintext/wrapped
keys — are load-bearing; removing any of them changes the trust model
further.

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

## 6. Secrets inventory — all of these must leave `.env`/git before production

| Secret | Used for | Notes |
|---|---|---|
| `GOOGLE_CLIENT_SECRET` | Keycloak Google IdP token exchange | Rejects login silently as a generic Keycloak error page if wrong/missing — easy to misdiagnose |
| `GOOGLE_WORKSPACE_CREDENTIALS_PATH` (JSON key) | Directory API DWD | See §1 |
| `KEYCLOAK_EVENTS_SECRET` | Shared secret for `/api/audit/keycloak-events` | `nginx/nginx.conf:29` explicitly 404s this path on the public edge — keep that rule if the proxy config is ever regenerated |
| `DB_PASSWORD`, `KEYCLOAK_ADMIN_PASSWORD` | Postgres / Keycloak bootstrap admin | Standard, but note `KEYCLOAK_ADMIN_PASSWORD` is a full Keycloak realm admin — treat as tier-0 |
| KMS key material | Recovery escrow (§4) | Never exported; only `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the specific key version for the runtime SA |

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
