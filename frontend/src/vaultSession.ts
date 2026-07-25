/*
 * Resumable vault unlock.
 *
 * Deriving the KEK from the passphrase is deliberately expensive (Argon2id), and
 * the OIDC login flow navigates the browser away and back, which tears the SPA
 * down completely. The result was that every re-login — including the automatic
 * redirect after a Keycloak session refresh — asked for the vault passphrase
 * again, even though nothing about the vault had changed.
 *
 * This module parks the *already unlocked* keys so the next boot can resume:
 *
 *  - The CryptoKey objects are non-extractable. IndexedDB stores them by
 *    structured clone, so the raw key bytes are handled only by the browser's
 *    crypto implementation and are never readable from JavaScript — not by this
 *    app, not by an injected script. There is no plaintext passphrase or key
 *    material at rest, unlike a naive sessionStorage cache.
 *  - The record is bound to one account (email) and carries an absolute expiry.
 *    Past the expiry, or for any other account, it is deleted and the passphrase
 *    prompt returns.
 *  - Locking or logging out deletes it immediately. Locking must stay a real
 *    lock, so it is never resumable.
 *
 * Trust model: whoever holds this browser profile *and* a live Keycloak session
 * can resume the vault until the expiry. That is strictly narrower than the
 * existing passkey unlock enrolment, which persists a wrapped passphrase
 * indefinitely; it is the same bargain a browser password manager makes.
 */

import type { VaultKeys } from './auth';

const DB_NAME = 'pm-vault-session';
const DB_VERSION = 1;
const STORE = 'session';
const RECORD_KEY = 'current';

/** Absolute cap on a resumable unlock. Long enough for a working day of
 *  Keycloak redirects, short enough that an unattended machine re-locks. */
export const VAULT_SESSION_TTL_MS = 8 * 60 * 60 * 1000;

interface StoredSession {
    email: string;
    kek: CryptoKey;
    privateKey: CryptoKey;
    publicKey: CryptoKey;
    expiresAt: number;
}

function openDb(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        request.onupgradeneeded = () => {
            if (!request.result.objectStoreNames.contains(STORE)) request.result.createObjectStore(STORE);
        };
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    });
}

function tx<T>(mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
    return openDb().then(db => new Promise<T>((resolve, reject) => {
        const request = run(db.transaction(STORE, mode).objectStore(STORE));
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
    }).finally(() => db.close()));
}

/** Best effort: a browser in private mode or with storage disabled must degrade
 *  to "ask for the passphrase", never to a crash on boot. */
export async function saveVaultSession(email: string, keys: VaultKeys): Promise<void> {
    const record: StoredSession = {
        email: email.toLowerCase(),
        kek: keys.kek,
        privateKey: keys.privateKey,
        publicKey: keys.publicKey,
        expiresAt: Date.now() + VAULT_SESSION_TTL_MS,
    };
    try {
        await tx('readwrite', store => store.put(record, RECORD_KEY));
    } catch { /* not resumable on this browser; unlock still worked */ }
}

export async function loadVaultSession(email: string): Promise<VaultKeys | null> {
    let record: StoredSession | undefined;
    try {
        record = await tx<StoredSession | undefined>('readonly', store => store.get(RECORD_KEY));
    } catch {
        return null;
    }
    if (!record) return null;
    // A stale or foreign record is evidence the browser was reused; drop it
    // rather than leaving it to expire on its own.
    if (record.email !== email.toLowerCase() || record.expiresAt <= Date.now()) {
        await clearVaultSession();
        return null;
    }
    // A structured clone that lost its CryptoKey identity (older browser, or a
    // record written by a previous schema) is unusable.
    if (!(record.kek instanceof CryptoKey) || !(record.privateKey instanceof CryptoKey)
        || !(record.publicKey instanceof CryptoKey)) {
        await clearVaultSession();
        return null;
    }
    return { kek: record.kek, privateKey: record.privateKey, publicKey: record.publicKey };
}

export async function clearVaultSession(): Promise<void> {
    try {
        await tx('readwrite', store => store.delete(RECORD_KEY));
    } catch { /* nothing to clear */ }
}
