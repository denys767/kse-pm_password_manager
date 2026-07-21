# KSE Password Manager — Chrome extension MVP

This isolated Manifest V3 extension uses the same client-side E2E chain as `frontend/src/crypto.ts`: passphrase-derived KEK → encrypted RSA private key → direct or collection-wrapped item key → AES-GCM password. The backend receives only ciphertext and wrapped keys. Vault keys and the OIDC access token remain only in service-worker memory; locking or worker restart requires unlocking again.

## Build and load unpacked

```bash
cd extension
npm install
npm run build
```

Open `chrome://extensions`, enable **Developer mode**, choose **Load unpacked**, and select `extension/dist`.

The manifest requests `host_permissions: ["http://*/*", "https://*/*"]` — Chrome shows this to the
user as "Read and change all your data on all websites." This is broader than the original
API-only MVP and is required for the always-on `content.ts` content script (autofill affordance,
new-credential capture, QR scanning — see below) to run on any page, not just the API/Keycloak
origins. `background.ts` also relies on this to reach `API_ORIGIN` for `/api/*` calls *and* to
post directly to the Keycloak token endpoint during login (both are same-origin-policy-exempt
for extension-page fetches only because they're covered by `host_permissions`); if you narrow
`host_permissions` back down, both of those need their own entry again or you'll see "Failed to
fetch" (CORS-blocked). `API_ORIGIN`/`OIDC_CLIENT_ID` in `src/config.ts` still need updating for a
non-localhost deployment; `OIDC_CLIENT_ID` defaults to the dedicated `kse-pm-extension` client.

### Features

For a non-localhost deployment, set build-time values instead of editing source:

```bash
VITE_API_ORIGIN=https://pm.example.com VITE_OIDC_CLIENT_ID=kse-pm-extension npm run build
```

- **Fill / Copy** (popup) — unchanged from the original MVP, strict origin match only.
- **Inline autofill icon** — `content.ts` marks password fields on pages with a matching saved
  item with a small 🔑 button (Shadow DOM, no page-CSS leakage) that triggers the same `autofill`
  flow as the popup's Fill button.
- **Auto-detected new credentials** — a `submit` listener on any page captures
  `{url, username, password}` from forms containing a password field. If no existing item matches
  that origin+username, `background.ts` creates one automatically (owner-wrapped with the user's
  public key, `defaultSyncMode` from `/api/settings`) and the content script shows a small toast.
  It never overwrites an existing saved password — only creates when nothing matches.
- **Suggested password on sign-up** — on forms whose password inputs are marked
  `autocomplete="new-password"`, the extension offers **Generate secure password**.
  It fills password and confirmation inputs; the value is only offered for
  encrypted vault storage after the registration form is submitted.
- **TOTP QR scan** — popup's **Scan QR (2FA)** button messages the content script, which scans
  every `<img>`/`<canvas>` on the current page with `jsqr`, looking for a decoded `otpauth://`
  string (typical of a site's "scan this QR to set up 2FA" screen). A match is merged into the
  selected item's existing encrypted payload (`totpSeed`) without touching its other fields, the
  same way the web app's Add/Edit dialog stores it — the code then shows up in both places.
  Cross-origin images with no CORS headers taint the canvas and are silently skipped (browser
  security, not a bug — screenshot or same-origin-served QR images work).

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
7. Open a login page with a matching saved item — verify the inline 🔑 button appears next to the password field and fills it on click.
8. Submit a login form on a site with no matching saved item (real login or a throwaway test form) — verify a new item appears in the vault afterward, and that submitting the same origin+username again does *not* create a duplicate.
9. On a site's 2FA setup screen (or any page with a QR `<img>`), open the popup, press **Scan QR (2FA)** on the matching item, and verify the same 6-digit code as the site's own authenticator shows up in the web app's item dialog afterward.
