import { API_ORIGIN, DEFAULT_CLIPBOARD_CLEAR_SECONDS, OIDC_CLIENT_ID } from './config';
import * as pmc from './crypto';
import { matchesOrigin } from './origin';
import type { Collection, FrontendConfig, PasswordItem, Settings, UserKeysDto } from './types';

interface VaultKeys { kek: CryptoKey; privateKey: CryptoKey; }
let token: string | undefined;
let vaultKeys: VaultKeys | undefined;
let creatingOffscreen: Promise<void> | undefined;

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
    try { vaultKeys = { kek, privateKey: await pmc.importEncryptedPrivateKey(stored.encryptedPrivateKey, stored.privateKeyIv, kek) }; }
    catch { throw new Error('Невірний passphrase для цього vault.'); }
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

chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
    void (async () => {
        const m = message as { type: string; item?: PasswordItem };
        if (m.type === 'login') { await login(); return { loggedIn: true }; }
        if (m.type === 'lock') { vaultKeys = undefined; return { locked: true }; }
        if (m.type === 'status') return { loggedIn: Boolean(token), unlocked: Boolean(vaultKeys) };
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
        throw new Error('Unknown extension message.');
    })().then(sendResponse, (error: Error) => sendResponse({ error: error.message }));
    return true;
});
