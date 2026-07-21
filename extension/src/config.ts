/** Build-time deployment configuration. Use an exact API origin, never a user-supplied URL. */
export const API_ORIGIN = 'http://localhost:8080';
/** Dedicated public Keycloak client; it must own the exact Chromium redirect URI. */
export const OIDC_CLIENT_ID = 'kse-pm-extension';
export const DEFAULT_CLIPBOARD_CLEAR_SECONDS = 20;
