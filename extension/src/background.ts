import { API_ORIGIN, DEFAULT_CLIPBOARD_CLEAR_SECONDS, OIDC_CLIENT_ID } from './config';
import * as pmc from './crypto';
import { matchesOrigin } from './origin';
import { emptyPayload, parsePayload, serializePayload } from './payload';
import { assertionResponse, createResponse } from './webauthn';
import type { Collection, FrontendConfig, PasskeyCredential, PasswordItem, Settings, UserKeysDto } from './types';

interface VaultKeys { kek: CryptoKey; privateKey: CryptoKey; publicKey: CryptoKey; }
let token: string | undefined;
let vaultKeys: VaultKeys | undefined;
let creatingOffscreen: Promise<void> | undefined;
let passkeyAttached = false;
const canceledWebAuthnRequests = new Set<number>();

function b64url(bytes: Uint8Array): string { return btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', ''); }
async function sha256B64url(value: string): Promise<string> { return b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))); }
function randomB64url(size: number): string { return b64url(crypto.getRandomValues(new Uint8Array(size))); }
function callbackParam(url: string, name: string): string | null { return new URL(url).searchParams.get(name); }
async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
    if (!token) throw new Error('Увійдіть через Keycloak.');
    const response = await fetch(`${API_ORIGIN}${path}`, { ...init, headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', ...(init.headers ?? {}) } });
    if (!response.ok) throw new Error(`API error ${response.status}`);
    return response.status === 204 ? null as T : response.json() as Promise<T>;
}
// Avoid shadowing this authenticated API primitive in WebAuthn event handlers.
const requestApi = request;
async function config(): Promise<FrontendConfig> {
    const response = await fetch(`${API_ORIGIN}/api/config`);
    if (!response.ok) throw new Error('Не вдалося завантажити OIDC configuration.');
    const value = await response.json() as FrontendConfig;
    if (value.authMode !== 'oidc') throw new Error('Extension вимагає OIDC mode.');
    return value;
}
async function login(): Promise<void> {
    const c = await config();
    const verifier = randomB64url(32);
    const state = randomB64url(24);
    const redirectUri = chrome.identity.getRedirectURL('oidc');
    const authorization = new URL(`${c.keycloakUrl}/realms/${encodeURIComponent(c.realm)}/protocol/openid-connect/auth`);
    authorization.search = new URLSearchParams({ client_id: OIDC_CLIENT_ID, response_type: 'code', redirect_uri: redirectUri, scope: 'openid', state, code_challenge: await sha256B64url(verifier), code_challenge_method: 'S256' }).toString();
    const callback = await chrome.identity.launchWebAuthFlow({ url: authorization.toString(), interactive: true });
    if (!callback || callbackParam(callback, 'state') !== state) throw new Error('OIDC state validation failed.');
    const code = callbackParam(callback, 'code');
    if (!code) throw new Error(callbackParam(callback, 'error_description') ?? 'Keycloak did not return an authorization code.');
    const response = await fetch(`${c.keycloakUrl}/realms/${encodeURIComponent(c.realm)}/protocol/openid-connect/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: OIDC_CLIENT_ID, code, redirect_uri: redirectUri, code_verifier: verifier }) });
    if (!response.ok) throw new Error('Token exchange failed.');
    token = (await response.json() as { access_token: string }).access_token;
}
async function unlock(passphrase: string): Promise<void> {
    const stored = await request<UserKeysDto>('/api/keys/me');
    const kek = await pmc.deriveKek(passphrase, stored.kdfSalt, stored.kdfAlgorithm);
    try {
        vaultKeys = {
            kek,
            privateKey: await pmc.importEncryptedPrivateKey(stored.encryptedPrivateKey, stored.privateKeyIv, kek),
            publicKey: await pmc.importPublicKey(stored.publicKey),
        };
        await attachPasskeyProvider();
    } catch { throw new Error('Невірний passphrase для цього vault.'); }
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
async function useSystemAuthenticator(requestId: number, complete: (value: { requestId: number; error: { name: string; message: string } }) => Promise<void>): Promise<void> {
    // Proxy attachment suppresses the native authenticator. Detach before
    // responding so the site can retry and Chrome will use the system provider.
    await detachPasskeyProvider();
    if (!canceledWebAuthnRequests.has(requestId)) await complete({ requestId, error: { name: 'NotAllowedError', message: 'No matching vault passkey. The system authenticator is enabled; retry this request to use it.' } });
}
async function onCreatePasskey(request: { requestId: number; requestDetailsJson: string }): Promise<void> {
    try {
        if (!vaultKeys) return useSystemAuthenticator(request.requestId, chrome.webAuthenticationProxy.completeCreateRequest);
        const options = JSON.parse(request.requestDetailsJson) as Record<string, unknown>;
        const origin = options.origin; const items = await requestApi<PasswordItem[]>('/api/vault/items');
        const item = items.find(value => typeof origin === 'string' && matchesOrigin(value.url, origin) && value.accessRole !== 'PASSKEY_ONLY');
        if (!item) return useSystemAuthenticator(request.requestId, chrome.webAuthenticationProxy.completeCreateRequest);
        const result = await createResponse(options, item, vaultKeys.publicKey);
        await requestApi('/api/passkeys', { method: 'POST', body: JSON.stringify({ ...result.payload, algorithm: 'ES256' }) });
        if (!canceled(request.requestId)) await chrome.webAuthenticationProxy.completeCreateRequest({ requestId: request.requestId, responseJson: result.responseJson });
    } catch (error) { if (!canceled(request.requestId)) await chrome.webAuthenticationProxy.completeCreateRequest({ requestId: request.requestId, error: { name: 'NotAllowedError', message: (error as Error).message } }); }
}
async function onGetPasskey(request: { requestId: number; requestDetailsJson: string }): Promise<void> {
    try {
        if (!vaultKeys) return useSystemAuthenticator(request.requestId, chrome.webAuthenticationProxy.completeGetRequest);
        const options = JSON.parse(request.requestDetailsJson) as Record<string, unknown>; const rpId = options.rpId;
        if (typeof rpId !== 'string') throw new Error('Missing RP ID.');
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
/** Only ever creates a new item — never silently overwrites an existing saved password. */
async function saveCredentials(url: string, username: string, password: string): Promise<{ saved: boolean }> {
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
function fillFields(username: string, password: string): void {
    const visible = (element: HTMLInputElement) => element.offsetParent !== null && !element.disabled && !element.readOnly;
    const inputs = [...document.querySelectorAll<HTMLInputElement>('input')].filter(visible);
    const passwordInput = inputs.find((input) => input.type === 'password');
    const usernameInput = inputs.find((input) => input.autocomplete.includes('username') || input.type === 'email' || input.type === 'text');
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
chrome.alarms.onAlarm.addListener((alarm) => { if (alarm.name === 'clear-password-clipboard') void ensureOffscreen().then(() => chrome.runtime.sendMessage({ type: 'clipboard-clear' })); });

// MV3 service workers may be restarted between requests, so register every
// proxy listener synchronously at module evaluation time.
chrome.webAuthenticationProxy.onCreateRequest.addListener((request) => { void onCreatePasskey(request); });
chrome.webAuthenticationProxy.onGetRequest.addListener((request) => { void onGetPasskey(request); });
chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener((request) => { void chrome.webAuthenticationProxy.completeIsUvpaaRequest({ requestId: request.requestId, isUvpaa: Boolean(vaultKeys && passkeyAttached) }); });
chrome.webAuthenticationProxy.onRequestCanceled.addListener((requestId) => { canceledWebAuthnRequests.add(requestId); });

chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
    void (async () => {
        const m = message as { type: string; item?: PasswordItem };
        if (m.type === 'login') { await login(); return { loggedIn: true }; }
        if (m.type === 'lock') { vaultKeys = undefined; await detachPasskeyProvider(); return { locked: true }; }
        if (m.type === 'logout') { vaultKeys = undefined; token = undefined; await detachPasskeyProvider(); return { loggedOut: true }; }
        if (m.type === 'status') return { loggedIn: Boolean(token), unlocked: Boolean(vaultKeys), passkeyProvider: passkeyAttached };
        if (m.type === 'unlock') { await unlock((message as { passphrase: string }).passphrase); return { unlocked: true }; }
        if (m.type === 'items') return await request<PasswordItem[]>('/api/vault/items');
        if (m.type === 'copy' && m.item) { const value = await secrets(m.item); await copy(value.password); void request(`/api/vault/items/${m.item.id}/copy-event`, { method: 'POST' }); return { copied: true }; }
        if (m.type === 'autofill' && m.item) {
            const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
            if (!matchesOrigin(m.item.url, tab?.url)) throw new Error('URL запису не збігається з origin активної вкладки.');
            if (!tab?.id) throw new Error('Немає активної вкладки.');
            const value = await secrets(m.item); await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: fillFields, args: [value.username, value.password] });
            return { filled: true };
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
