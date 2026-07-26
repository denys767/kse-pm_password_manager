/** Build-time deployment configuration. Never accept the API origin from page content or user input. */
export const API_ORIGIN = (import.meta.env.VITE_API_ORIGIN || 'http://localhost:8080').replace(/\/$/, '');
/** The SPA and the API are the same origin (nginx proxies "/" to the app) —
 *  this is also the only origin externally_connectable trusts. */
export const APP_ORIGIN = API_ORIGIN;
/** Dedicated public Keycloak client; it must own the exact Chromium redirect URI. */
export const OIDC_CLIENT_ID = import.meta.env.VITE_OIDC_CLIENT_ID || 'kse-pm-extension';
export const DEFAULT_CLIPBOARD_CLEAR_SECONDS = 20;
/**
 * Idle minutes before the vault locks itself. The keys now survive a
 * service-worker restart, so something has to put a bound on how long an
 * unlocked vault sits in an unattended browser; this is that bound. Deliberate
 * use (fill, copy, unlock) pushes it out again.
 */
export const AUTO_LOCK_MINUTES = 15;
