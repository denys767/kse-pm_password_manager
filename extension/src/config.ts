/** Build-time deployment configuration. Never accept the API origin from page content or user input. */
export const API_ORIGIN = (import.meta.env.VITE_API_ORIGIN || 'http://localhost:8080').replace(/\/$/, '');
/** Dedicated public Keycloak client; it must own the exact Chromium redirect URI. */
export const OIDC_CLIENT_ID = import.meta.env.VITE_OIDC_CLIENT_ID || 'kse-pm-extension';
export const DEFAULT_CLIPBOARD_CLEAR_SECONDS = 20;
