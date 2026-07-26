/**
 * The other half of the extension's bridge (extension/src/bridge.ts). The
 * extension cannot run the vault's WebAuthn ceremony itself — the PRF-wrapped
 * passphrase lives in this page's localStorage, bound to this origin as the
 * credential's RP ID — so unlocking the extension with it means this page runs
 * the ceremony and hands the plaintext passphrase to the extension's worker
 * over chrome.runtime.connect, exactly as if it had been typed into the popup.
 *
 * Only present in a Chromium browser with the extension installed; every
 * export here degrades to a no-op otherwise. Guarded by the extension's own
 * externally_connectable + an origin check on its side — this page does not
 * need to (and cannot) prove its own identity beyond that.
 */

export interface ExtensionStatus { loggedIn: boolean; unlocked: boolean }

export interface ExtensionBridgeHandlers {
    onStatus?: (status: ExtensionStatus) => void;
    /** The extension wants to be unlocked; run the passkey ceremony (or show a
     *  fallback) and call notifyExtensionUnlocked with the recovered passphrase. */
    onRequestUnlock?: () => void;
    /** The extension (or another app tab) locked the vault. */
    onLocked?: () => void;
}

let port: ChromeRuntimePort | undefined;
let extensionId: string | undefined;
let handlers: ExtensionBridgeHandlers = {};
let reconnectTimer: number | undefined;

export function isExtensionBridgeAvailable(): boolean {
    return typeof chrome !== 'undefined' && typeof chrome.runtime?.connect === 'function';
}

export function initExtensionBridge(id: string, newHandlers: ExtensionBridgeHandlers): void {
    extensionId = id;
    handlers = newHandlers;
    connect();
}

function connect(): void {
    if (!extensionId || !isExtensionBridgeAvailable()) return;
    try {
        port = chrome!.runtime!.connect(extensionId, { name: 'pm-vault-bridge' });
    } catch {
        scheduleReconnect();
        return;
    }
    port.onMessage.addListener((message: unknown) => {
        const m = message as { type: string; loggedIn?: boolean; unlocked?: boolean };
        if (m.type === 'status') handlers.onStatus?.({ loggedIn: Boolean(m.loggedIn), unlocked: Boolean(m.unlocked) });
        else if (m.type === 'request-unlock') handlers.onRequestUnlock?.();
        else if (m.type === 'vault-locked') handlers.onLocked?.();
    });
    port.onDisconnect.addListener(() => { port = undefined; scheduleReconnect(); });
    port.postMessage({ type: 'hello' });
}

function scheduleReconnect(): void {
    if (reconnectTimer !== undefined) return;
    reconnectTimer = window.setTimeout(() => { reconnectTimer = undefined; connect(); }, 5000);
}

/** Sends the passphrase recovered from this session's own unlock (passphrase
 *  form or vault passkey) so the extension can unlock exactly as it would from
 *  its popup. Never stored here — only relayed. */
export function notifyExtensionUnlock(passphrase: string): void {
    port?.postMessage({ type: 'unlock', passphrase });
}

export function notifyExtensionLock(): void {
    port?.postMessage({ type: 'lock' });
}
