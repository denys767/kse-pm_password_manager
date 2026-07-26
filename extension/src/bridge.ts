import { APP_ORIGIN } from './config';

/**
 * The app<->extension passkey-unlock bridge.
 *
 * The SPA holds the vault's WebAuthn passkey (PRF-wrapped passphrase in its own
 * localStorage, bound to the app's origin as RP ID) — the extension cannot run
 * that ceremony itself. So unlocking the extension with the app's passkey means
 * the app runs the ceremony and hands the *passphrase* over; the extension then
 * unlocks exactly as it would from the popup form. Manifest `externally_connectable`
 * only gates which origins may open a port at all — every message must still be
 * re-checked against `port.sender.origin` here, since a compromised or
 * misconfigured entry there would otherwise be enough on its own.
 *
 * Lock state syncs both ways: a lock in either context should mean "locked
 * everywhere". Unlock does not: the extension has no way to hand the app raw KEK
 * bytes without regressing the app's own non-extractable-CryptoKey model, so an
 * extension-side passphrase unlock only notifies the app — it does not unlock it.
 */
export interface BridgeHandlers {
    status(): Promise<{ loggedIn: boolean; unlocked: boolean }>;
    unlock(passphrase: string): Promise<void>;
    lock(): Promise<void>;
}

const ports = new Set<chrome.runtime.Port>();
let pendingUnlockRequest = false;

function sendRequestUnlock(port: chrome.runtime.Port): void {
    try { port.postMessage({ type: 'request-unlock' }); } catch { /* port gone */ }
}

export function setupExternalBridge(handlers: BridgeHandlers): void {
    chrome.runtime.onConnectExternal.addListener((port) => {
        if (port.sender?.origin !== APP_ORIGIN) { port.disconnect(); return; }
        ports.add(port);
        port.onDisconnect.addListener(() => ports.delete(port));
        // A tab opened specifically to answer an unlock-via-app request from
        // the popup, connecting for the first time: it has missed the request
        // that was broadcast (or never broadcast, since it did not exist yet).
        if (pendingUnlockRequest) { pendingUnlockRequest = false; sendRequestUnlock(port); }
        port.onMessage.addListener((message: unknown) => {
            const m = message as { type: string; passphrase?: string };
            void (async () => {
                try {
                    if (m.type === 'hello') { port.postMessage({ type: 'status', ...(await handlers.status()) }); return; }
                    if (m.type === 'unlock' && m.passphrase) { await handlers.unlock(m.passphrase); port.postMessage({ type: 'unlocked' }); return; }
                    if (m.type === 'lock') { await handlers.lock(); port.postMessage({ type: 'locked' }); return; }
                } catch (e) { port.postMessage({ type: 'error', message: (e as Error).message }); }
            })();
        });
    });
}

/** Every path that clears the vault keys — manual lock, idle auto-lock, logout —
 *  must call this so an open app tab locks along with the extension. */
export function broadcastVaultLocked(): void {
    for (const port of ports) { try { port.postMessage({ type: 'vault-locked' }); } catch { /* port gone */ } }
}

/** Asks a connected app tab to run its passkey ceremony and send back an
 *  `unlock` message. Returns false when no app tab has the bridge open yet —
 *  the request is remembered and served to the next tab that connects, so the
 *  caller can simply open one. */
export function requestUnlockFromApp(): boolean {
    if (ports.size === 0) { pendingUnlockRequest = true; return false; }
    for (const port of ports) sendRequestUnlock(port);
    return true;
}

export function connectedAppTabId(): number | undefined {
    for (const port of ports) { if (port.sender?.tab?.id !== undefined) return port.sender.tab.id; }
    return undefined;
}
