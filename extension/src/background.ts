import { API_ORIGIN, APP_ORIGIN, AUTO_LOCK_MINUTES, DEFAULT_CLIPBOARD_CLEAR_SECONDS, OIDC_CLIENT_ID } from './config';
import * as pmc from './crypto';
import { matchesOrigin } from './origin';
import { emptyPayload, parsePayload, serializePayload } from './payload';
import { clearSession, clearVaultFromSession, patchSession, readSession } from './session';
import { assertionResponse, createResponse } from './webauthn';
import { broadcastVaultLocked, requestUnlockFromApp, setupExternalBridge } from './bridge';
import type { Collection, FrontendConfig, KeyDistribution, PasskeyCredential, PasswordItem, Settings, UserKeysDto } from './types';

interface VaultKeys { kek: CryptoKey; privateKey: CryptoKey; publicKey: CryptoKey; }
let token: string | undefined;
let refreshToken: string | undefined;
let vaultKeys: VaultKeys | undefined;
let creatingOffscreen: Promise<void> | undefined;
let passkeyAttached = false;
/** Set while the OIDC sign-in window is open; see loginWithoutProxyingKeycloak. */
let signingIn = false;
const canceledWebAuthnRequests = new Set<number>();

const AUTO_LOCK_ALARM = 'vault-auto-lock';
const PASSKEY_SYNC_ALARM = 'passkey-key-distribution';

function b64url(bytes: Uint8Array): string { return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''); }
async function sha256B64url(value: string): Promise<string> { return b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))); }
function randomB64url(size: number): string { return b64url(crypto.getRandomValues(new Uint8Array(size))); }

/**
 * Rebuilds this worker's state from chrome.storage.session.
 *
 * Every entry point awaits this, because MV3 may have thrown the previous
 * worker away between any two messages. Memoized per worker lifetime, so the
 * common case costs one resolved promise.
 */
let hydrating: Promise<void> | undefined;
function hydrate(): Promise<void> {
    hydrating ??= (async () => {
        const stored = await readSession();
        token = stored.accessToken;
        refreshToken = stored.refreshToken;
        if (stored.kek && stored.encryptedPrivateKey && stored.privateKeyIv && stored.publicKey) {
            try {
                const kek = await pmc.importKek(pmc.fromBase64(stored.kek));
                vaultKeys = {
                    kek,
                    privateKey: await pmc.importEncryptedPrivateKey(stored.encryptedPrivateKey, stored.privateKeyIv, kek),
                    publicKey: await pmc.importPublicKey(stored.publicKey),
                };
                await attachPasskeyProvider();
            } catch {
                // Unreadable stored material is not something to limp along
                // with; drop it and ask for the passphrase.
                vaultKeys = undefined;
                await clearVaultFromSession();
            }
        }
    })();
    return hydrating;
}

/** Pushes the idle auto-lock out. Called on deliberate vault use, not on
 * background chores — otherwise the reconcile alarm would keep the vault
 * unlocked forever on its own. */
async function touchVault(): Promise<void> {
    if (!vaultKeys) return;
    await patchSession({ lastUsedAt: Date.now() });
    chrome.alarms.create(AUTO_LOCK_ALARM, { delayInMinutes: AUTO_LOCK_MINUTES });
}

async function refreshAccessToken(): Promise<boolean> {
    if (!refreshToken) return false;
    const c = await config();
    const response = await fetch(`${c.keycloakUrl}/realms/${encodeURIComponent(c.realm)}/protocol/openid-connect/token`,
        { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ grant_type: 'refresh_token', client_id: OIDC_CLIENT_ID, refresh_token: refreshToken }) });
    if (!response.ok) { refreshToken = undefined; return false; }
    const body = await response.json() as { access_token: string; refresh_token?: string };
    token = body.access_token;
    if (body.refresh_token) refreshToken = body.refresh_token;
    await patchSession({ accessToken: token, refreshToken });
    return true;
}

async function request<T>(path: string, init: RequestInit = {}, retrying = false): Promise<T> {
    await hydrate();
    if (!token) throw new Error('Увійдіть через Keycloak.');
    const response = await fetch(`${API_ORIGIN}${path}`, { ...init, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...(init.headers ?? {}) } });
    // Keycloak access tokens last minutes. Without this the extension appeared
    // to log itself out several times an hour; the session was fine, only the
    // access token had aged out.
    if (response.status === 401 && !retrying && await refreshAccessToken()) {
        return request<T>(path, init, true);
    }
    if (!response.ok) throw new Error(`API error ${response.status}`);
    return response.status === 204 ? null as T : response.json() as Promise<T>;
}
// Avoid shadowing this authenticated API primitive in WebAuthn event handlers.
const requestApi = request;
let cachedConfig: FrontendConfig | undefined;
async function config(): Promise<FrontendConfig> {
    if (cachedConfig) return cachedConfig;
    const response = await fetch(`${API_ORIGIN}/api/config`);
    if (!response.ok) throw new Error('Не вдалося завантажити OIDC configuration.');
    const value = await response.json() as FrontendConfig;
    if (value.authMode !== 'oidc') throw new Error('Extension вимагає OIDC mode.');
    cachedConfig = value;
    return value;
}
async function login(): Promise<void> {
    const c = await config();
    const verifier = randomB64url(32);
    const state = randomB64url(24);
    const redirectUri = `${APP_ORIGIN}/extension-callback`;
    const authorization = new URL(`${c.keycloakUrl}/realms/${encodeURIComponent(c.realm)}/protocol/openid-connect/auth`);
    // offline_access is what makes the refresh token above possible; without it
    // Keycloak hands back only a short-lived access token.
    authorization.search = new URLSearchParams({ client_id: OIDC_CLIENT_ID, response_type: 'code', redirect_uri: redirectUri, scope: 'openid offline_access', state, code_challenge: await sha256B64url(verifier), code_challenge_method: 'S256' }).toString();
    const code = await launchSignInTab(authorization.toString(), state);
    const response = await fetch(`${c.keycloakUrl}/realms/${encodeURIComponent(c.realm)}/protocol/openid-connect/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: OIDC_CLIENT_ID, code, redirect_uri: redirectUri, code_verifier: verifier }) });
    if (!response.ok) throw new Error('Token exchange failed.');
    const body = await response.json() as { access_token: string; refresh_token?: string };
    token = body.access_token;
    refreshToken = body.refresh_token;
    await patchSession({ accessToken: token, refreshToken });
}

const SIGN_IN_TIMEOUT_MS = 5 * 60_000;

/**
 * Runs Keycloak's login in a real, unrestricted tab with the WebAuthn proxy
 * out of the way, and waits for ExtensionCallbackPage (the SPA's
 * /extension-callback route) to relay back the authorization code.
 *
 * This replaced chrome.identity.launchWebAuthFlow, whose stripped browser
 * context could not reliably run platform WebAuthn — Keycloak's own passkey
 * login needs a normal tab, which this now is.
 *
 * While the vault is unlocked this extension owns the browser's WebAuthn
 * requests. That includes the ones Keycloak's own login page makes — so
 * "Sign in with a passkey" was handed to onGetPasskey, which looked for a vault
 * item matching the Keycloak origin, found none, and answered NotAllowedError.
 * Passkey sign-in was not unavailable so much as intercepted; detaching the
 * proxy for the duration of sign-in, same as before, fixes that here too.
 */
async function launchSignInTab(url: string, expectedState: string): Promise<string> {
    const wasAttached = passkeyAttached;
    signingIn = true;
    if (wasAttached) await detachPasskeyProvider();
    const tab = await chrome.tabs.create({ url, active: true });
    try {
        return await new Promise<string>((resolve, reject) => {
            let settled = false;
            const finish = (run: () => void) => { if (settled) return; settled = true; cleanup(); run(); };
            const onMessage = (message: unknown, sender: { origin?: string; tab?: { id?: number } }, sendResponse: (r: unknown) => void): boolean => {
                const m = message as { type?: string; code?: string; state?: string; error?: string };
                if (m.type !== 'oidc-callback' || sender.origin !== APP_ORIGIN) return false;
                sendResponse({ received: true });
                finish(() => {
                    if (m.state !== expectedState) { reject(new Error('OIDC state validation failed.')); return; }
                    if (!m.code) { reject(new Error(m.error ?? 'Keycloak did not return an authorization code.')); return; }
                    resolve(m.code);
                });
                return true;
            };
            const onRemoved = (tabId: number) => { if (tabId === tab.id) finish(() => reject(new Error('Sign-in was cancelled.'))); };
            const timeout = setTimeout(() => finish(() => reject(new Error('Sign-in timed out.'))), SIGN_IN_TIMEOUT_MS);
            function cleanup(): void {
                clearTimeout(timeout);
                chrome.runtime.onMessageExternal.removeListener(onMessage);
                chrome.tabs.onRemoved.removeListener(onRemoved);
            }
            chrome.runtime.onMessageExternal.addListener(onMessage);
            chrome.tabs.onRemoved.addListener(onRemoved);
        });
    } finally {
        signingIn = false;
        if (tab.id !== undefined) { try { await chrome.tabs.remove(tab.id); } catch { /* user already closed it */ } }
        if (wasAttached) await attachPasskeyProvider();
    }
}

async function unlock(passphrase: string): Promise<void> {
    const stored = await request<UserKeysDto>('/api/keys/me');
    const kekBytes = await pmc.deriveKekBytes(passphrase, stored.kdfSalt, stored.kdfAlgorithm);
    const kek = await pmc.importKek(kekBytes);
    try {
        vaultKeys = {
            kek,
            privateKey: await pmc.importEncryptedPrivateKey(stored.encryptedPrivateKey, stored.privateKeyIv, kek),
            publicKey: await pmc.importPublicKey(stored.publicKey),
        };
    } catch { throw new Error('Невірний passphrase для цього vault.'); }
    await patchSession({
        kek: pmc.toBase64(kekBytes),
        encryptedPrivateKey: stored.encryptedPrivateKey,
        privateKeyIv: stored.privateKeyIv,
        publicKey: stored.publicKey,
        lastUsedAt: Date.now(),
    });
    chrome.alarms.create(AUTO_LOCK_ALARM, { delayInMinutes: AUTO_LOCK_MINUTES });
    chrome.alarms.create(PASSKEY_SYNC_ALARM, { delayInMinutes: 1, periodInMinutes: 5 });
    await attachPasskeyProvider();
    // The owner is the only party who can hand a shared passkey to its
    // grantees, and unlocking is the first moment it can.
    void reconcilePasskeyKeys();
}

async function lockVault(): Promise<void> {
    vaultKeys = undefined;
    await clearVaultFromSession();
    await chrome.alarms.clear(AUTO_LOCK_ALARM);
    await chrome.alarms.clear(PASSKEY_SYNC_ALARM);
    await detachPasskeyProvider();
    // Every path here — manual lock, idle auto-lock, logout — should lock an
    // open app tab too, not just this extension.
    broadcastVaultLocked();
}

/**
 * Hands each PASSKEY_ONLY (and other passkey-capable) grantee a copy of the
 * credential key, wrapped to their public key.
 *
 * The server cannot do this — it never holds an unwrapped credential key — and
 * the web client is deliberately not allowed to, so the owner's extension is
 * the only place it can happen. Until this existed, granting PASSKEY_ONLY
 * created a permission that entitled the grantee to a credential they could
 * never actually decrypt, and their passkey list simply stayed empty.
 */
async function reconcilePasskeyKeys(): Promise<void> {
    if (!vaultKeys) return;
    let work: KeyDistribution[];
    try { work = await request<KeyDistribution[]>('/api/passkeys/key-distribution'); }
    catch { return; /* offline, locked out, or an older backend: the next pass retries */ }
    for (const credential of work) {
        try {
            const credentialKey = await pmc.unwrapItemKey(credential.wrappedCredentialKeyForMe, vaultKeys.privateKey);
            for (const grantee of credential.pending) {
                const wrapped = await pmc.wrapItemKey(credentialKey, await pmc.importPublicKey(grantee.publicKey));
                await request(`/api/passkeys/${credential.id}/wrapped-keys`, {
                    method: 'PUT',
                    body: JSON.stringify({ userEmail: grantee.email, wrappedCredentialKey: wrapped }),
                });
            }
        } catch { /* one credential failing must not stop the rest */ }
    }
}
async function detachPasskeyProvider(): Promise<void> {
    passkeyAttached = false;
    try { await chrome.webAuthenticationProxy.detach(); } catch { /* already detached or unavailable */ }
}
async function attachPasskeyProvider(): Promise<void> {
    if (!vaultKeys || passkeyAttached) return;
    try { await chrome.webAuthenticationProxy.attach(); passkeyAttached = true; }
    catch { passkeyAttached = false; /* another provider owns the system authenticator */ }
}
function canceled(id: number): boolean { return canceledWebAuthnRequests.has(id) || !vaultKeys || !passkeyAttached; }

/**
 * Requests this extension must never answer: the ones aimed at our own
 * Keycloak or API. A vault passkey is for some third-party site; a WebAuthn
 * prompt on the sign-in page is the user authenticating *to us*, and swallowing
 * it is how passkey login broke.
 */
async function isOwnOrigin(rpIdOrOrigin: unknown): Promise<boolean> {
    if (typeof rpIdOrOrigin !== 'string' || !rpIdOrOrigin) return false;
    let hosts: string[];
    try {
        const c = await config();
        hosts = [new URL(c.keycloakUrl).hostname, new URL(API_ORIGIN).hostname];
    } catch { return false; }
    const candidate = rpIdOrOrigin.includes('://') ? new URL(rpIdOrOrigin).hostname : rpIdOrOrigin;
    return hosts.some((host) => host === candidate || host.endsWith(`.${candidate}`));
}
async function useSystemAuthenticator(requestId: number, complete: (value: { requestId: number; error: { name: string; message: string } }) => Promise<void>): Promise<void> {
    // Proxy attachment suppresses the native authenticator. Detach before
    // responding so the site can retry and Chrome will use the system provider.
    await detachPasskeyProvider();
    if (!canceledWebAuthnRequests.has(requestId)) await complete({ requestId, error: { name: 'NotAllowedError', message: 'No matching vault passkey. The system authenticator is enabled; retry this request to use it.' } });
}
async function onCreatePasskey(request: { requestId: number; requestDetailsJson: string }): Promise<void> {
    try {
        await hydrate();
        if (!vaultKeys || signingIn) return useSystemAuthenticator(request.requestId, chrome.webAuthenticationProxy.completeCreateRequest);
        const options = JSON.parse(request.requestDetailsJson) as Record<string, unknown>;
        const origin = options.origin;
        if (await isOwnOrigin(origin) || await isOwnOrigin((options.rp as { id?: string } | undefined)?.id)) {
            return useSystemAuthenticator(request.requestId, chrome.webAuthenticationProxy.completeCreateRequest);
        }
        const items = await requestApi<PasswordItem[]>('/api/vault/items');
        const item = items.find(value => typeof origin === 'string' && matchesOrigin(value.url, origin) && value.accessRole !== 'PASSKEY_ONLY');
        if (!item) return useSystemAuthenticator(request.requestId, chrome.webAuthenticationProxy.completeCreateRequest);
        const result = await createResponse(options, item, vaultKeys.publicKey);
        await requestApi('/api/passkeys', { method: 'POST', body: JSON.stringify({ ...result.payload, algorithm: 'ES256' }) });
        if (!canceled(request.requestId)) await chrome.webAuthenticationProxy.completeCreateRequest({ requestId: request.requestId, responseJson: result.responseJson });
    } catch (error) { if (!canceled(request.requestId)) await chrome.webAuthenticationProxy.completeCreateRequest({ requestId: request.requestId, error: { name: 'NotAllowedError', message: (error as Error).message } }); }
}
async function onGetPasskey(request: { requestId: number; requestDetailsJson: string }): Promise<void> {
    try {
        await hydrate();
        if (!vaultKeys || signingIn) return useSystemAuthenticator(request.requestId, chrome.webAuthenticationProxy.completeGetRequest);
        const options = JSON.parse(request.requestDetailsJson) as Record<string, unknown>; const rpId = options.rpId;
        if (typeof rpId !== 'string') throw new Error('Missing RP ID.');
        if (await isOwnOrigin(rpId)) {
            return useSystemAuthenticator(request.requestId, chrome.webAuthenticationProxy.completeGetRequest);
        }
        const candidates = await requestApi<PasskeyCredential[]>(`/api/passkeys?rpId=${encodeURIComponent(rpId)}`);
        const allowed = options.allowCredentials as Array<{ id?: string }> | undefined;
        const passkey = candidates.find(candidate => !allowed?.length || allowed.some(entry => entry.id === candidate.credentialId));
        if (!passkey) return useSystemAuthenticator(request.requestId, chrome.webAuthenticationProxy.completeGetRequest);
        const result = await assertionResponse(options, passkey, vaultKeys.privateKey);
        await requestApi(`/api/passkeys/${passkey.id}/counter`, { method: 'POST', body: JSON.stringify({ signCounter: result.nextCounter }) });
        if (!canceled(request.requestId)) await chrome.webAuthenticationProxy.completeGetRequest({ requestId: request.requestId, responseJson: result.responseJson });
    } catch (error) { if (!canceled(request.requestId)) await chrome.webAuthenticationProxy.completeGetRequest({ requestId: request.requestId, error: { name: 'NotAllowedError', message: (error as Error).message } }); }
}
async function itemKey(item: PasswordItem, collections: Collection[]): Promise<CryptoKey> {
    if (!vaultKeys) throw new Error('Vault заблокований.');
    if (item.syncMode === 'LOCAL_ONLY' && item.kekWrappedKey) return pmc.unwrapItemKeyWithKek(item.kekWrappedKey.ct, item.kekWrappedKey.iv, vaultKeys.kek);
    if (item.wrappedKey) return pmc.unwrapItemKey(item.wrappedKey, vaultKeys.privateKey);
    if (item.collectionId && item.collectionWrappedKey && item.collectionWrappedKeyIv) {
        const collection = collections.find((value) => value.id === item.collectionId);
        if (!collection) throw new Error('Немає ключа колекції.');
        const collectionKey = await pmc.unwrapItemKey(collection.myWrappedKey, vaultKeys.privateKey);
        return pmc.unwrapItemKeyWithKek(item.collectionWrappedKey, item.collectionWrappedKeyIv, collectionKey);
    }
    throw new Error('Немає обгорнутого ключа запису.');
}
async function secrets(item: PasswordItem): Promise<{ username: string; password: string }> {
    const collections = await request<Collection[]>('/api/collections');
    const key = await itemKey(item, collections);
    return { username: item.username ?? '', password: await pmc.decryptField(key, item.encryptedPassword, item.passwordIv) };
}
async function totpCode(item: PasswordItem): Promise<string | null> {
    if (!item.encryptedNotes || !item.notesIv) return null;
    const collections = await request<Collection[]>('/api/collections');
    const key = await itemKey(item, collections);
    const payload = parsePayload(await pmc.decryptField(key, item.encryptedNotes, item.notesIv));
    return payload.totpSeed ? pmc.generateTotp(payload.totpSeed) : null;
}
/**
 * Only ever creates a new item — never silently overwrites an existing saved
 * password, and never creates the same one twice.
 *
 * The duplicate-check below reads the vault and then posts, which is a window
 * two concurrent calls can both walk through: a double-clicked submit button,
 * or a site that submits its own form again, produced two identical records.
 * Serializing on (origin, username) closes it — the second caller waits for the
 * first and then sees the item it created.
 */
const savesInFlight = new Map<string, Promise<{ saved: boolean }>>();
function saveCredentials(url: string, username: string, password: string): Promise<{ saved: boolean }> {
    let origin: string;
    try { origin = new URL(url).origin; } catch { origin = url; }
    const key = `${origin}|${username}`;
    const existing = savesInFlight.get(key);
    if (existing) return existing;
    const attempt = createCredentials(url, username, password).finally(() => savesInFlight.delete(key));
    savesInFlight.set(key, attempt);
    return attempt;
}

async function createCredentials(url: string, username: string, password: string): Promise<{ saved: boolean }> {
    await hydrate();
    if (!vaultKeys) throw new Error('Vault заблокований — відкрийте extension і розблокуйте його.');
    const items = await request<PasswordItem[]>('/api/vault/items');
    const exists = items.some((item) => matchesOrigin(item.url, url) && (item.username ?? '') === username);
    if (exists) return { saved: false };
    const settings = await request<Settings>('/api/settings');
    const itemKeyMaterial = await pmc.generateItemKey();
    const passwordField = await pmc.encryptField(itemKeyMaterial, password);
    const notesField = await pmc.encryptField(itemKeyMaterial, serializePayload(emptyPayload()));
    let name: string;
    try { name = new URL(url).hostname; } catch { name = url; }
    await request('/api/vault/items', {
        method: 'POST',
        body: JSON.stringify({
            name, url, username: username || null,
            encryptedPassword: passwordField.ct, passwordIv: passwordField.iv,
            encryptedNotes: notesField.ct, notesIv: notesField.iv,
            type: 'LOGIN', itemType: 'PERSONAL', syncMode: settings.defaultSyncMode,
            wrappedKey: await pmc.wrapItemKey(itemKeyMaterial, vaultKeys.publicKey),
        }),
    });
    return { saved: true };
}
/** Merges a scanned otpauth URI into the item's existing encrypted payload without touching its other fields. */
async function attachTotp(item: PasswordItem, otpauthUri: string): Promise<void> {
    const collections = await request<Collection[]>('/api/collections');
    const key = await itemKey(item, collections);
    const payload = item.encryptedNotes && item.notesIv
        ? parsePayload(await pmc.decryptField(key, item.encryptedNotes, item.notesIv))
        : emptyPayload();
    payload.totpSeed = otpauthUri;
    const notesField = await pmc.encryptField(key, serializePayload(payload));
    await request(`/api/vault/items/${item.id}`, {
        method: 'PUT',
        body: JSON.stringify({
            name: item.name, url: item.url, username: item.username,
            encryptedPassword: item.encryptedPassword, passwordIv: item.passwordIv,
            encryptedNotes: notesField.ct, notesIv: notesField.iv,
            tags: item.tags, type: item.type, itemType: item.itemType, syncMode: item.syncMode,
        }),
    });
}
/**
 * Runs in the page. Fills the password field and the username field that
 * belongs to it.
 *
 * Two things used to go wrong here. It searched the whole document for "the
 * first visible text input", which on a page with a search box or a cookie
 * banner is not the username field at all; it now scopes the search to the
 * password field's own form and takes the nearest text/email input *before* it,
 * which is what a login form actually looks like. And it skipped any empty
 * value — so an item saved without a username silently filled nothing, which
 * read as "autofill only fills the password".
 */
function fillFields(username: string, password: string): void {
    const visible = (element: HTMLInputElement) => element.offsetParent !== null && !element.disabled && !element.readOnly;
    const all = [...document.querySelectorAll<HTMLInputElement>('input')].filter(visible);
    const passwordInput = all.find((input) => input.type === 'password');
    const scope = passwordInput?.form
        ? [...passwordInput.form.querySelectorAll<HTMLInputElement>('input')].filter(visible)
        : all;
    const looksLikeUsername = (input: HTMLInputElement) =>
        input.autocomplete.includes('username') || input.autocomplete.includes('email')
        || input.type === 'email' || input.type === 'text' || input.type === 'tel';
    const before = passwordInput ? scope.slice(0, scope.indexOf(passwordInput)) : scope;
    const usernameInput = [...before].reverse().find(looksLikeUsername) ?? scope.find(looksLikeUsername);
    const set = (input: HTMLInputElement | undefined, value: string) => {
        if (!input || !value) return;
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
        setter?.call(input, value); input.dispatchEvent(new Event('input', { bubbles: true })); input.dispatchEvent(new Event('change', { bubbles: true }));
    };
    set(usernameInput, username); set(passwordInput, password);
}
async function ensureOffscreen(): Promise<void> {
    if (await chrome.offscreen.hasDocument()) return;
    creatingOffscreen ??= chrome.offscreen.createDocument({ url: 'offscreen.html', reasons: ['CLIPBOARD'], justification: 'Clear copied passwords after the configured timeout.' }).finally(() => { creatingOffscreen = undefined; });
    await creatingOffscreen;
}
async function copy(value: string): Promise<void> {
    await ensureOffscreen(); await chrome.runtime.sendMessage({ type: 'clipboard-copy', value });
    let seconds = DEFAULT_CLIPBOARD_CLEAR_SECONDS;
    try { seconds = Math.max(1, (await request<Settings>('/api/settings')).clipboardClearSeconds || seconds); } catch { /* default is intentionally safe */ }
    chrome.alarms.create('clear-password-clipboard', { when: Date.now() + seconds * 1000 });
}
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === 'clear-password-clipboard') { void ensureOffscreen().then(() => chrome.runtime.sendMessage({ type: 'clipboard-clear' })); return; }
    if (alarm.name === AUTO_LOCK_ALARM) {
        void (async () => {
            await hydrate();
            // The alarm may have been set before the last deliberate use; only
            // lock if the vault really has been idle for the whole window.
            const { lastUsedAt } = await readSession();
            const idleFor = Date.now() - (lastUsedAt ?? 0);
            if (idleFor >= AUTO_LOCK_MINUTES * 60_000) await lockVault();
            else chrome.alarms.create(AUTO_LOCK_ALARM, { delayInMinutes: AUTO_LOCK_MINUTES - idleFor / 60_000 });
        })();
        return;
    }
    if (alarm.name === PASSKEY_SYNC_ALARM) {
        void hydrate().then(reconcilePasskeyKeys);
    }
});

// MV3 service workers may be restarted between requests, so register every
// proxy listener synchronously at module evaluation time.
setupExternalBridge({
    status: async () => { await hydrate(); return { loggedIn: Boolean(token), unlocked: Boolean(vaultKeys) }; },
    unlock: async (passphrase) => { await hydrate(); await unlock(passphrase); },
    lock: async () => { await hydrate(); await lockVault(); },
});
chrome.webAuthenticationProxy.onCreateRequest.addListener((request) => { void onCreatePasskey(request); });
chrome.webAuthenticationProxy.onGetRequest.addListener((request) => { void onGetPasskey(request); });
chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener((request) => { void chrome.webAuthenticationProxy.completeIsUvpaaRequest({ requestId: request.requestId, isUvpaa: Boolean(vaultKeys && passkeyAttached) }); });
chrome.webAuthenticationProxy.onRequestCanceled.addListener((requestId) => { canceledWebAuthnRequests.add(requestId); });

chrome.runtime.onMessage.addListener((message: unknown, sender, sendResponse) => {
    void (async () => {
        await hydrate();
        const m = message as { type: string; item?: PasswordItem };
        if (m.type === 'login') { await login(); return { loggedIn: true }; }
        if (m.type === 'lock') { await lockVault(); return { locked: true }; }
        if (m.type === 'logout') { await lockVault(); token = undefined; refreshToken = undefined; await clearSession(); return { loggedOut: true }; }
        if (m.type === 'status') return { loggedIn: Boolean(token), unlocked: Boolean(vaultKeys), passkeyProvider: passkeyAttached };
        if (m.type === 'unlock') { await unlock((message as { passphrase: string }).passphrase); return { unlocked: true }; }
        if (m.type === 'unlock-via-app') {
            // If an app tab already has the bridge open, ask it directly and
            // bring it to the front — the passkey ceremony needs a focused
            // document, and a background tab leaves the user staring at
            // nothing. Otherwise open a new tab; it will run the ceremony as
            // soon as it connects (see the pending-request handling in bridge.ts).
            const { served, tabId, windowId } = requestUnlockFromApp();
            let focused = false;
            if (served && tabId !== undefined) {
                try {
                    await chrome.tabs.update(tabId, { active: true });
                    if (windowId !== undefined) await chrome.windows.update(windowId, { focused: true });
                    focused = true;
                } catch { /* the tab went away between the port message and now */ }
            }
            if (!served || !focused) await chrome.tabs.create({ url: API_ORIGIN, active: true });
            return { requested: true, focused };
        }
        if (m.type === 'items') return await request<PasswordItem[]>('/api/vault/items');
        if (m.type === 'copy' && m.item) {
            // Resolved fresh from the server rather than trusted from the
            // caller: Passkey Only must never yield the raw password, and a
            // stale or crafted message must not be able to lie about the role.
            const fresh = (await request<PasswordItem[]>('/api/vault/items')).find((value) => value.id === m.item!.id);
            if (!fresh) throw new Error('Запис не знайдено.');
            if (fresh.accessRole === 'PASSKEY_ONLY') throw new Error('Passkey Only: пароль недоступний для копіювання.');
            const value = await secrets(fresh);
            await copy(value.password); await touchVault(); void request(`/api/vault/items/${fresh.id}/copy-event`, { method: 'POST' });
            return { copied: true };
        }
        if (m.type === 'autofill') {
            // By id from the content script, by value from the popup. The
            // content script runs in a page we do not control, so it is handed
            // labels to draw a picker with and nothing else — never the item
            // ciphertext it would need to be trusted with otherwise.
            const itemId = (message as { itemId?: string }).itemId;
            const item = itemId
                ? (await request<PasswordItem[]>('/api/vault/items')).find((value) => value.id === itemId)
                : m.item;
            if (!item) throw new Error('Запис не знайдено.');
            // Fill the frame that asked, not whatever happens to be focused.
            // Content scripts run in every frame of every page, so resolving
            // the active tab let a page in a background tab drive a fill into
            // the document the user was actually looking at — and lost the
            // right target anyway if focus moved between click and fill. The
            // popup has no sender tab, so it still means "the active one".
            const senderTabId = sender?.tab?.id;
            const target = senderTabId !== undefined
                ? { id: senderTabId, url: sender?.origin ?? sender?.tab?.url }
                : await chrome.tabs.query({ active: true, currentWindow: true })
                    .then(([tab]) => (tab?.id === undefined ? undefined : { id: tab.id, url: tab.url }));
            if (!target) throw new Error('Немає активної вкладки.');
            if (!matchesOrigin(item.url, target.url)) throw new Error('URL запису не збігається з origin вкладки.');
            const value = await secrets(item);
            await chrome.scripting.executeScript({ target: { tabId: target.id }, func: fillFields, args: [value.username, value.password] });
            await touchVault();
            return { filled: true };
        }
        // Just enough for the in-page picker to label its options. While the
        // vault is locked, usernames are still plaintext on the server, but
        // handing them to the page would defeat locking — only whether a
        // match exists is disclosed.
        if (m.type === 'autofill-candidates') {
            const url = (message as { url: string }).url;
            const items = await request<PasswordItem[]>('/api/vault/items');
            const matching = items.filter((item) => matchesOrigin(item.url, url));
            if (!vaultKeys) return { locked: true, hasMatch: matching.length > 0, candidates: [] };
            return { locked: false, hasMatch: matching.length > 0, candidates: matching.map((item) => ({ id: item.id, name: item.name, username: item.username ?? '' })) };
        }
        if (m.type === 'totp' && m.item) return { code: await totpCode(m.item) };
        if (m.type === 'save-credentials') {
            const { url, username, password } = message as { url: string; username: string; password: string };
            return await saveCredentials(url, username, password);
        }
        if (m.type === 'attach-totp' && m.item) {
            await attachTotp(m.item, (message as { otpauthUri: string }).otpauthUri);
            return { attached: true };
        }
        throw new Error('Unknown extension message.');
    })().then(sendResponse, (error: Error) => sendResponse({ error: error.message }));
    return true;
});
