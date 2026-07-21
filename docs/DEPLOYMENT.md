# Production deployment

## Web application and Keycloak

Choose public HTTPS origins before deployment, for example `https://pm.example.com`
for the application and `https://auth.pm.example.com` for Keycloak. Do not retain
`localhost` values outside local development.

1. Set strong values for `DB_PASSWORD`, `KEYCLOAK_ADMIN_PASSWORD`,
   `KEYCLOAK_ADMIN_CLIENT_SECRET`, and `KEYCLOAK_EVENTS_SECRET`; store them in a
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
