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

Create a dedicated service account — **do not download a JSON key for it**.
The backend authenticates keyless via impersonation:

1. Give the caller identity that will run the app (a GCE/GKE-attached service
   account in production, or your own `gcloud` login for local testing) the
   role `roles/iam.serviceAccountTokenCreator` on the target service account:
   ```
   gcloud iam service-accounts add-iam-policy-binding <target-sa-email> \
     --member="<caller-principal>" --role="roles/iam.serviceAccountTokenCreator"
   ```
2. Enable domain-wide delegation for the target service account and, in the
   Workspace Admin Console, authorize its OAuth **Client ID** (not the caller's)
   for the scopes below — this step is unchanged from the key-based setup;
   delegation is granted per client ID regardless of how the app authenticates
   as the caller.
3. Configure `GOOGLE_WORKSPACE_SERVICE_ACCOUNT_EMAIL`, `GOOGLE_WORKSPACE_ADMIN_EMAIL`,
   `GOOGLE_WORKSPACE_DOMAIN`, and (when needed) `GOOGLE_WORKSPACE_CUSTOMER_ID`.
   On GCP compute this is all that's needed — Application Default Credentials
   (ADC) resolve through the instance metadata server automatically. Off GCP,
   set `GOOGLE_APPLICATION_CREDENTIALS` to a mounted `gcloud auth
   application-default login` file instead (`docker-compose.prod.yml` has the
   commented block for this) — that file is a revocable, expiring user
   credential scoped only to `iam.serviceAccounts.signJwt`, not a standing
   Directory-API-capable key.

At request time, `GoogleWorkspaceDirectoryClient` calls the IAM Credentials
API (`signJwt`) as the caller identity to sign a domain-wide-delegation JWT
assertion for `GOOGLE_WORKSPACE_ADMIN_EMAIL`, then exchanges it at Google's
OAuth token endpoint for a short-lived Directory API access token (cached
until near-expiry). No private key material ever exists on disk. See
`docs/SECURITY.md` §1 for the reasoning.

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

## Recovery escrow and KMS runbook

Recovery wrapping changes the trust model: a recovery-wrapped item, collection,
or passkey key lets an authorized backend administrator recover that ciphertext
through Cloud KMS. This is therefore **not** a zero-knowledge deployment.

Use a versioned Cloud KMS asymmetric RSA key configured for
`RSA_DECRYPT_OAEP_2048_SHA256` (or the approved RSA-OAEP-SHA256 variant), expose
only its public key to clients, and grant the runtime service account the minimum
KMS encrypt/decrypt permissions for that key version. Do not give application
operators broad KMS administration. Recovery operators must use step-up SSO,
provide a case/ticket reason, and retain the resulting audit event and owner
notification. Never place wrapped keys, decrypted keys, or plaintext in logs.

Keep automatic group provisioning/recovery disabled until coverage reporting
shows sufficient recovery wraps for the affected records. On key-version
rotation, publish the new public version first, backfill wraps on unlock, check
coverage, and only then retire the old KMS version.

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
