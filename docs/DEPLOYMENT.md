# Production deployment

## Web application and Keycloak

Choose public HTTPS origins before deployment, for example `https://pm.example.com`
for the application and `https://auth.pm.example.com` for Keycloak. Do not retain
`localhost` values outside local development.

1. Set strong values for `DB_PASSWORD`, `KEYCLOAK_ADMIN_PASSWORD`,
   and `KEYCLOAK_EVENTS_SECRET`; store them in a
   secret manager or protected environment file, not in git.
2. Configure TLS certificates and reverse-proxy hostnames. Set
   `KEYCLOAK_HOSTNAME=https://auth.pm.example.com`; the production compose file
   configures proxy headers as `xforwarded` and PostgreSQL for Keycloak. Set the
   set the backend `KEYCLOAK_ISSUER_URI` to
   `https://auth.pm.example.com/realms/kse-pm`.
3. In Keycloak, update `kse-pm-web` valid redirect URIs and web origins to
   `https://pm.example.com/*` and `https://pm.example.com`. Configure the Google
   provider redirect URI as
   `https://auth.pm.example.com/realms/kse-pm/broker/google/endpoint`.
4. Build and start the stack with `docker compose -f docker-compose.prod.yml up -d --build`.
   Keep PostgreSQL and Keycloak off public Docker ports; expose only the TLS
   reverse proxy. Verify `/actuator/health`, login, logout, WebAuthn, and an
   external-share link.

## Google Workspace Directory and Drive

Create a dedicated service account and enable domain-wide delegation for it: in
the Workspace Admin Console, authorize its OAuth **Client ID** for the scopes
below. That step is the same whichever credential mode you pick.

Then pick the credential the backend authenticates *with*. It has to renew
itself forever — this is a 24/7 service, and there is nobody to press a button
at 3 a.m.:

**Mode A — workload identity federation (recommended off GCP; keyless).** No
service-account key ever exists: the app authenticates to *this stack's own
Keycloak* as a confidential client using `client_credentials` (a machine grant —
no human involved, so no reauth policy can expire it), then exchanges that OIDC
token at Google's Security Token Service for a federated access token that
signs the delegation assertion. This is the mode to reach for when Workspace
admins won't authorize a downloaded key, which is the common case.

One-time GCP setup (needs only IAM permissions on the project — no Workspace
Admin Console access beyond the DWD authorization above):

```
gcloud iam workload-identity-pools create kse-pm --location=global

gcloud iam workload-identity-pools providers create-oidc keycloak \
  --workload-identity-pool=kse-pm --location=global \
  --issuer-uri=https://auth.pm.example.com/realms/kse-pm \
  --attribute-mapping=google.subject=assertion.sub \
  --attribute-condition="assertion.azp == 'kse-pm-federation'"
```

No `--allowed-audiences` is needed: the `kse-pm-federation` client carries an
audience mapper that stamps `WORKSPACE_FEDERATION_AUDIENCE` (the provider
resource name) into the token's `aud`, which is exactly what Google STS expects
by default.

**`--attribute-condition` is not optional here, and the reason is specific to
this stack.** The realm named in `--issuer-uri` is the same realm that
authenticates ordinary end users. Without the condition, the pool admits *every*
identity that realm issues a token for — every person with an account — and the
only thing standing between one of them and impersonating the service account is
that no IAM binding names their `sub`. That is one careless
`principalSet://…/*` binding away from domain-wide impersonation for every
delegated scope: read the whole directory, and read or delete any user's
`appDataFolder`, which is every encrypted attachment in the organization. The
condition closes it at the provider, so a later mistake in the binding cannot
reopen it.

For the same reason, keep the binding below scoped to a single
`principal://…/subject/<sub>`. Never grant `roles/iam.workloadIdentityUser` or
`roles/iam.serviceAccountTokenCreator` to `principalSet://…/*`, and never to the
whole pool or provider — most tutorials show exactly that, and it is wrong for
any pool whose issuer also serves human logins.

The IAM binding identifies the Keycloak service account by the `sub` claim of
its token, which is a Keycloak user UUID. Read it from a real token rather than
guessing:

```
SUB=$(curl -s -X POST \
  https://auth.pm.example.com/realms/kse-pm/protocol/openid-connect/token \
  -d grant_type=client_credentials \
  -d client_id=kse-pm-federation \
  -d client_secret="$WORKSPACE_FEDERATION_CLIENT_SECRET" \
  | python3 -c 'import sys,json,base64;t=json.load(sys.stdin)["access_token"].split(".")[1];print(json.loads(base64.urlsafe_b64decode(t+"=="))["sub"])')

gcloud iam service-accounts add-iam-policy-binding <target-sa-email> \
  --role="roles/iam.serviceAccountTokenCreator" \
  --member="principal://iam.googleapis.com/projects/<project-number>/locations/global/workloadIdentityPools/kse-pm/subject/${SUB}"
```

That `sub` is stable for the life of the Keycloak client. Recreating the realm
or the client mints a new one, so the binding has to be redone if you ever do.

Google validates Keycloak's tokens against `issuer-uri`'s
`/.well-known/openid-configuration` and JWKS, so that URL must be reachable
over HTTPS with a publicly trusted certificate. If it is not (an internal-only
Keycloak), pass `--jwk-json-path=<realm JWKS>` at provider-creation time
instead of `--issuer-uri`, and re-upload it whenever the realm's signing keys
rotate.

`realm-export.json` already defines the Keycloak side: a confidential client
`kse-pm-federation` with `serviceAccountsEnabled: true` and no interactive
flows. Set its secret and the app's federation settings:

```
WORKSPACE_FEDERATION_TOKEN_URL=https://auth.pm.example.com/realms/kse-pm/protocol/openid-connect/token
WORKSPACE_FEDERATION_CLIENT_ID=kse-pm-federation
WORKSPACE_FEDERATION_CLIENT_SECRET=<matches the Keycloak client secret>
WORKSPACE_FEDERATION_AUDIENCE=//iam.googleapis.com/projects/<project-number>/locations/global/workloadIdentityPools/kse-pm/providers/keycloak
```

`GOOGLE_WORKSPACE_CREDENTIALS_PATH` must stay empty for this mode to take effect.

**Mode B — attached service account (GCE/GKE only).** Leave both
`GOOGLE_WORKSPACE_CREDENTIALS_PATH` and the federation settings empty.
Application Default Credentials resolve through the metadata server and the app
impersonates the target service account, which needs:

```
gcloud iam service-accounts add-iam-policy-binding <target-sa-email> \
  --member="serviceAccount:<attached-sa-email>" \
  --role="roles/iam.serviceAccountTokenCreator"
```

**Mode C — service-account key (last resort).** Only when neither of the above
is available — it needs a downloaded private key, which most Workspace admins
will not authorize. The key signs the delegation assertion locally: no second
identity, no IAM Credentials call, nothing that expires.

```
gcloud iam service-accounts keys create workspace-sa.json \
  --iam-account=<target-sa-email>
```

Mount it read-only and point the app at it:

```
GOOGLE_WORKSPACE_CREDENTIALS_PATH=/run/secrets/workspace-sa.json
```

The same key also backs encrypted Drive attachments. Treat it as a tier-0
secret: keep it out of the image and out of git, restrict file permissions, and
rotate by replacing the file — the app re-reads it on the next token renewal,
no restart needed.

**Not a mode: `gcloud auth application-default login`.** That is a *user*
credential. Google's reauth policy expires it within hours
(`invalid_grant / invalid_rapt`), taking directory suggestions, group sync and
new shares with it. It is fine for a laptop; it can never run a deployment. The
application detects it and shows it on the Admin tab —
`GET /api/admin/workspace/directory-status` reports
`credentialUnattended: false`. Under the `prod` profile it goes further and
**refuses to start**, because a warning in a log nobody is reading is not a
signal, and the failure it predicts arrives hours later looking like something
else entirely.

Whichever mode you pick, configure `GOOGLE_WORKSPACE_SERVICE_ACCOUNT_EMAIL`,
`GOOGLE_WORKSPACE_ADMIN_EMAIL`, `GOOGLE_WORKSPACE_DOMAIN` and (when needed)
`GOOGLE_WORKSPACE_CUSTOMER_ID`. In Mode C the key mints the domain-wide-delegated
token for `GOOGLE_WORKSPACE_ADMIN_EMAIL` directly; in Modes A and B the app
calls the IAM Credentials API (`signJwt`) as the federated or attached identity
to sign the delegation assertion and exchanges it at Google's OAuth token
endpoint. Either way the resulting Directory/Drive access token is short-lived
and cached until near-expiry — see `DelegatedTokenMinter`.

Delegate only these scopes to the service-account client ID:

```text
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.group.readonly
https://www.googleapis.com/auth/admin.directory.group.member.readonly
https://www.googleapis.com/auth/drive.appdata
```

Exactly those four, and no others. Domain-wide delegation is authorized per
client ID × scope, and the app builds the delegation assertion itself — it puts
the subject and the scope list into the JWT — so the Admin Console entry is the
*only* thing bounding what a compromised backend could ask for. Two substitutions
matter especially: the writable `admin.directory.user` would let it edit
accounts, and plain `drive` would reach past `appDataFolder` into every user's
actual Drive. If you want the Directory and Drive blast radii to be separable at
all, use two service accounts and authorize each for only its own scopes.

**The delegation subject.** `GOOGLE_WORKSPACE_ADMIN_EMAIL` is the account the
backend impersonates for every Directory call. Make it a dedicated, licensed,
non-human account holding a *custom* admin role with only Users → Read and
Groups → Read — not a super-admin. The read-only scopes already cap what a token
can do; the subject caps what a scope-authorization mistake can do, and the two
failures are independent.

Enable both Admin SDK Directory API and Google Drive API in the Google Cloud
project. The Directory sync runs every 15 minutes and can be triggered by an
administrator at `POST /api/admin/workspace/refresh`; verify its result before
relying on local role/revocation decisions. The Drive scope is used only with
owner impersonation and each record owner's `appDataFolder`. Do not set an
application attachment-size cap: Drive/Workspace quotas and protocol limits are
the authoritative limits. Attachments are streamed end to end (chunked resumable
upload, streamed download) precisely so that policy is real rather than
theoretical — a byte[]-buffered implementation would have made any "no cap"
policy a memory-exhaustion risk in practice. Because of that, both hops in
front of the app must not silently reintroduce a cap: nginx sets
`client_max_body_size 0` and `proxy_request_buffering off` on the attachment
routes (see `nginx/nginx.conf`), and `server.tomcat.max-swallow-size=-1` stops
Tomcat from aborting a large upload it decided to discard.

### What happens when Google is unreachable anyway

Credentials get revoked, networks break, Google has incidents. None of that may
take the vault down:

- Startup never requires a working credential; the app boots and reports the
  problem.
- A delegated token already in hand keeps being used until it truly expires,
  and is renewed proactively every ten minutes
  (`pm.google-workspace.token-refresh-ms`) so failures show up in the logs and
  on the Admin tab before a user meets them.
- **Directory suggestions and recipient validation are served from the local
  Workspace snapshot in the first place**, not just when Google is down. They
  reach Google only when the snapshot has nothing to offer, which in practice
  means a cold start before the first sync. So an outage costs sharing nothing
  at all: the picker was already answering from materialized data.
- That is also a load decision, not only a resilience one. A type-ahead going
  live to Google meant five Directory API calls per keystroke, authenticated as
  the Workspace admin and driven by any signed-in user — enough to exhaust the
  per-customer quota and take sharing down for everybody. Google is now called
  by the 15-minute synchronizer and essentially nothing else.
- Group membership resolution still asks Google first and falls back to the
  snapshot on failure. The Admin tab says when that is happening.
- The synchronizer itself never falls back (it would be syncing with itself), it
  just leaves the snapshot untouched and retries: every minute until the first
  snapshot lands, then `pm.google-workspace.sync-interval-ms`.
- While the snapshot has *never* been fetched, an in-domain account that passed
  SSO is admitted as an ordinary `USER` so a Google problem cannot lock everyone
  out. Roles and revocations are enforced as soon as a sync succeeds. Set
  `WORKSPACE_PROVISIONAL_ACCESS=false` to fail closed instead.

`GET /api/admin/workspace/directory-status` (admin) reports the credential mode,
whether it can run unattended, the last successful sync, the last error, and
whether lookups are currently served from the snapshot.

## Vault passphrase loss

There is no key escrow and no administrator recovery path: a lost vault
passphrase cannot be recovered by the operator. The user resets their vault from
the unlock screen ("Forgot your Vault passphrase?"), which requires a fresh SSO
authentication, forces ownership of any shared record or team collection to be
handed to a successor who already has encrypted access, and then deletes the
remaining owned records before a new keypair is created. Plan offboarding around
that: records that must outlive an account have to be shared (or live in a
collection) before the account goes away.

## Chrome extension

Build the extension against the public application origin:

```bash
cd extension
VITE_API_ORIGIN=https://pm.example.com VITE_OIDC_CLIENT_ID=kse-pm-extension npm ci
VITE_API_ORIGIN=https://pm.example.com VITE_OIDC_CLIENT_ID=kse-pm-extension npm run build
```

Publish `extension/dist` with a stable extension identity. In Keycloak create the
public client `kse-pm-extension` with Authorization Code + PKCE S256 and add this
exact redirect URI:

```text
https://pm.example.com/extension-callback
```

Sign-in opens that URL in a normal browser tab (`chrome.tabs.create`), not
`chrome.identity.launchWebAuthFlow` — the latter's stripped browser context
could not reliably run Keycloak's own platform-WebAuthn passkey login. The tab
lands on the SPA's `/extension-callback` route (`ExtensionCallbackPage.tsx`),
which relays the authorization code back to the extension over
`chrome.runtime.sendMessage` and never sees a token exchange; the background
worker closes the tab once it has the code.

The extension fetches `/api/config` from `VITE_API_ORIGIN` and then uses the
public Keycloak URL returned by the app. No localhost API address appears in a
production extension bundle when `VITE_API_ORIGIN` is supplied.

The virtual authenticator requires Chrome 115+ and the
`chrome.webAuthenticationProxy` permission. Keep the extension locked unless
the user's vault is unlocked; detach the proxy on lock or logout so Chrome can
fall back to the system authenticator.

### Unlocking the extension with the app's vault passkey

The extension's popup only ever asks for the passphrase directly, or asks the
web app to unlock it. The two are bridged through
`externally_connectable` (`extension/public/manifest.json`) — the app's build
patches this to the deployment's own origin (`VITE_API_ORIGIN`), and
`chrome.runtime.connect(extensionId)` from the SPA (`frontend/src/extensionBridge.ts`)
is re-validated against that origin again on the extension side
(`extension/src/bridge.ts`) before anything is trusted. The extension cannot run
the vault's WebAuthn ceremony itself — the PRF-wrapped passphrase lives in the
app's own `localStorage`, bound to the app's origin as the credential's RP ID —
so the app runs the ceremony and hands the extension the plaintext passphrase,
exactly as if it had been typed into the popup. Locking propagates both ways;
unlocking only flows app → extension, since the extension has no way to hand
the app raw key material without regressing the app's own
non-extractable-`CryptoKey` session model.

`GET /api/config` reports `extensionId` (`pm.extension.id`, defaulting to the
ID Chrome derives from the `key` pinned in `manifest.json`) so the SPA knows
which extension to connect to without hardcoding it.
