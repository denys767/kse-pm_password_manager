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
  --attribute-mapping=google.subject=assertion.sub
```

No `--allowed-audiences` is needed: the `kse-pm-federation` client carries an
audience mapper that stamps `WORKSPACE_FEDERATION_AUDIENCE` (the provider
resource name) into the token's `aud`, which is exactly what Google STS expects
by default.

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
application detects it, logs a warning at startup, and shows it on the Admin
tab — `GET /api/admin/workspace/directory-status` reports
`credentialUnattended: false`.

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

Enable both Admin SDK Directory API and Google Drive API in the Google Cloud
project. The Directory sync runs every 15 minutes and can be triggered by an
administrator at `POST /api/admin/workspace/refresh`; verify its result before
relying on local role/revocation decisions. The Drive scope is used only with
owner impersonation and each record owner's `appDataFolder`. Do not set an
application attachment-size cap: Drive/Workspace quotas and protocol limits are
the authoritative limits.

### What happens when Google is unreachable anyway

Credentials get revoked, networks break, Google has incidents. None of that may
take the vault down:

- Startup never requires a working credential; the app boots and reports the
  problem.
- A delegated token already in hand keeps being used until it truly expires,
  and is renewed proactively every ten minutes
  (`pm.google-workspace.token-refresh-ms`) so failures show up in the logs and
  on the Admin tab before a user meets them.
- **Directory suggestions, recipient validation and group membership fall back
  to the local Workspace snapshot** — the same data the synchronizer
  materialized. Sharing keeps working with slightly older data instead of an
  empty picker. The Admin tab says when this is happening.
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
https://<stable-extension-id>.chromiumapp.org/oidc
```

The extension fetches `/api/config` from `VITE_API_ORIGIN` and then uses the
public Keycloak URL returned by the app. No localhost API address appears in a
production extension bundle when `VITE_API_ORIGIN` is supplied.

The virtual authenticator requires Chrome 115+ and the
`chrome.webAuthenticationProxy` permission. Keep the extension locked unless
the user's vault is unlocked; detach the proxy on lock or logout so Chrome can
fall back to the system authenticator.
