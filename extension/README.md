# KSE Password Manager — Chrome extension MVP

This isolated Manifest V3 extension uses the same client-side E2E chain as `frontend/src/crypto.ts`: passphrase-derived KEK → encrypted RSA private key → direct or collection-wrapped item key → AES-GCM password. The backend receives only ciphertext and wrapped keys. Vault keys and the OIDC access token remain only in service-worker memory; locking or worker restart requires unlocking again.

## Build and load unpacked

```bash
cd extension
npm install
npm run build
```

Open `chrome://extensions`, enable **Developer mode**, choose **Load unpacked**, and select `extension/dist`.

The development manifest deliberately permits only `http://localhost:8080/*`. For a deployed environment, change `API_ORIGIN` in `src/config.ts` and the matching `host_permissions` value in `public/manifest.json`, then rebuild. `OIDC_CLIENT_ID` in the same file defaults to the dedicated `kse-pm-extension` client.

In Keycloak create (or configure) a separate public OIDC client for the extension. Its valid redirect URI must be the **exact** value Chrome displays for this installed extension:

```text
https://<extension-id>.chromiumapp.org/oidc
```

Set Authorization Code flow with PKCE `S256`; do not enable direct grants. The concrete ID is stable only when the extension has a stable key/published identity, so it is intentionally not added as a wildcard to the realm export. Chrome extension host permissions allow extension-page API calls without broadening backend CORS.

## Checks

```bash
npm test
```

This bundles the extension, then checks strict origin equality (including scheme/port/subdomain rejection) and AES-GCM decrypt fixtures with both legacy PBKDF2 and Argon2id KEKs.

## Manual E2E checklist

1. Start KSE API/Keycloak and load the unpacked extension.
2. Configure the exact extension redirect URI in the extension OIDC client.
3. Click **Sign in**, complete Keycloak, and enter the existing vault passphrase.
4. Open a login page whose scheme, host and port exactly equal a stored item URL; search and press **Fill**.
5. Verify a sibling subdomain, a different scheme, and a different port show no matching record and cannot autofill.
6. Press **Copy**, paste once, wait for the configured timeout, and verify the clipboard is cleared. Press **Lock** and verify Fill/Copy require unlock.

Auto-saving newly entered credentials is intentionally out of scope.
