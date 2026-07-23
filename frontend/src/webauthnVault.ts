/*
 * Client-side "unlock the Vault with WebAuthn" (a platform authenticator such as
 * Touch ID, Windows Hello or an Android screen lock).
 *
 * The vault is end-to-end encrypted: the passphrase never reaches the server, so
 * this feature cannot be a server-side WebAuthn ceremony. Instead it relies on
 * the WebAuthn PRF extension (backed by CTAP hmac-secret): the authenticator
 * deterministically derives a 32-byte secret from a fixed salt, gated behind user
 * verification (biometric / PIN). That secret AES-GCM-wraps the vault passphrase,
 * and the wrapped blob + credential id + salt live in this browser's localStorage.
 *
 * Consequences (by design, same trust model as a browser password manager):
 *  - It is per-device / per-browser. Clearing site data or moving to another
 *    machine means re-enrolling — the passphrase (and Google SSO) always still work.
 *  - The passphrase in plaintext only ever exists transiently in memory while
 *    wrapping (on enable) or right after unwrapping (on unlock), exactly like a
 *    normal unlock. At rest we hold only ciphertext the authenticator can unlock.
 */

import { tr } from './i18n';

const RP_NAME = 'KSE Password Manager';
const STORAGE_PREFIX = 'pm.vault-webauthn.';

interface Wrapped {
    ct: string;
    iv: string;
}

interface StoredCredential {
    credentialId: string; // base64
    prfSalt: string;      // base64 — fixed per enrolment, replayed on every unlock
    wrap: Wrapped;        // passphrase wrapped with the PRF-derived AES key
    createdAt: string;    // ISO 8601
}

// The DOM lib in TypeScript 5.6 does not yet model the PRF extension, so the
// relevant inputs/outputs are described narrowly here and cast at the call site.
interface PrfExtensionOutput { prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } } }

const te = new TextEncoder();
const td = new TextDecoder();

const b64 = (buf: ArrayBuffer | Uint8Array): string =>
    btoa(String.fromCharCode(...new Uint8Array(buf as ArrayBuffer)));

const unb64 = (str: string): Uint8Array<ArrayBuffer> => {
    const raw = atob(str);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes;
};

const randomBytes = (length: number): Uint8Array<ArrayBuffer> =>
    crypto.getRandomValues(new Uint8Array(length));

const storageKey = (email: string): string => `${STORAGE_PREFIX}${email.toLowerCase()}`;

/** Stable ≤64-byte WebAuthn user handle so re-enrolment reuses one credential slot. */
async function userHandle(email: string): Promise<Uint8Array<ArrayBuffer>> {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(email.toLowerCase())));
}

/** WebAuthn + PRF need a secure context; Safari/older browsers may lack the API. */
export function isWebAuthnSupported(): boolean {
    return typeof window !== 'undefined'
        && typeof window.PublicKeyCredential === 'function'
        && typeof navigator.credentials?.create === 'function';
}

export function hasVaultWebAuthn(email: string): boolean {
    return localStorage.getItem(storageKey(email)) !== null;
}

/** ISO timestamp of the stored enrolment, or null when none exists. */
export function vaultWebAuthnEnrolledAt(email: string): string | null {
    const stored = readStored(email);
    return stored?.createdAt ?? null;
}

export function removeVaultWebAuthn(email: string): void {
    localStorage.removeItem(storageKey(email));
}

function readStored(email: string): StoredCredential | null {
    const raw = localStorage.getItem(storageKey(email));
    if (!raw) return null;
    try {
        return JSON.parse(raw) as StoredCredential;
    } catch {
        localStorage.removeItem(storageKey(email));
        return null;
    }
}

async function wrapPassphrase(secret: Uint8Array<ArrayBuffer>, passphrase: string): Promise<Wrapped> {
    const key = await crypto.subtle.importKey('raw', secret, { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = randomBytes(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(passphrase));
    return { ct: b64(ct), iv: b64(iv) };
}

async function unwrapPassphrase(secret: Uint8Array<ArrayBuffer>, wrap: Wrapped): Promise<string> {
    const key = await crypto.subtle.importKey('raw', secret, { name: 'AES-GCM' }, false, ['decrypt']);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(wrap.iv) }, key, unb64(wrap.ct));
    return td.decode(plaintext);
}

/** Runs a WebAuthn assertion with PRF and returns the derived secret bytes. */
async function evaluatePrf(credentialId: BufferSource, prfSalt: BufferSource): Promise<ArrayBuffer> {
    const assertion = await navigator.credentials.get({
        publicKey: {
            challenge: randomBytes(32),
            allowCredentials: [{ id: credentialId, type: 'public-key' }],
            userVerification: 'required',
            timeout: 60_000,
            extensions: { prf: { eval: { first: prfSalt } } } as unknown as AuthenticationExtensionsClientInputs,
        },
    }) as PublicKeyCredential | null;
    if (!assertion) throw new Error(tr('Автентифікацію Passkey скасовано.', 'Passkey authentication was cancelled.'));
    const results = (assertion.getClientExtensionResults() as PrfExtensionOutput).prf?.results?.first;
    if (!results) throw new Error(tr('Автентифікатор не повернув PRF-секрет.', 'The authenticator did not return a PRF secret.'));
    return results;
}

/**
 * Enrols this browser: creates a platform credential with PRF, derives the secret
 * and stores the passphrase wrapped under it. Throws (storing nothing) when the
 * authenticator cannot do PRF, so the caller can surface a clear message.
 */
export async function registerVaultWebAuthn(
    user: { email: string; displayName: string }, passphrase: string): Promise<void> {
    if (!isWebAuthnSupported()) {
        throw new Error(tr('Passkey не підтримується у цьому браузері.', 'Passkeys are not supported in this browser.'));
    }
    const prfSalt = randomBytes(32);
    const credential = await navigator.credentials.create({
        publicKey: {
            challenge: randomBytes(32),
            rp: { name: RP_NAME, id: window.location.hostname },
            user: { id: await userHandle(user.email), name: user.email, displayName: user.displayName || user.email },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
            authenticatorSelection: {
                authenticatorAttachment: 'platform',
                residentKey: 'discouraged',
                userVerification: 'required',
            },
            timeout: 60_000,
            attestation: 'none',
            extensions: { prf: { eval: { first: prfSalt } } } as unknown as AuthenticationExtensionsClientInputs,
        },
    }) as PublicKeyCredential | null;
    if (!credential) throw new Error(tr('Реєстрацію Passkey скасовано.', 'Passkey registration was cancelled.'));

    const output = credential.getClientExtensionResults() as PrfExtensionOutput;
    if (!output.prf || output.prf.enabled === false) {
        throw new Error(tr('Цей автентифікатор не підтримує PRF, тому розблокування Vault через Passkey недоступне на цьому пристрої.',
            'This authenticator does not support PRF, so unlocking the vault with a passkey is not available on this device.'));
    }

    // Some browsers return the PRF secret straight from create(); others only from
    // a follow-up assertion. Prefer the former (single prompt), fall back otherwise.
    const secret = output.prf.results?.first ?? await evaluatePrf(credential.rawId, prfSalt);

    const stored: StoredCredential = {
        credentialId: b64(credential.rawId),
        prfSalt: b64(prfSalt),
        wrap: await wrapPassphrase(new Uint8Array(secret), passphrase),
        createdAt: new Date().toISOString(),
    };
    localStorage.setItem(storageKey(user.email), JSON.stringify(stored));
}

/** Prompts the authenticator and returns the recovered vault passphrase. */
export async function unlockWithVaultWebAuthn(email: string): Promise<string> {
    if (!isWebAuthnSupported()) {
        throw new Error(tr('Passkey не підтримується у цьому браузері.', 'Passkeys are not supported in this browser.'));
    }
    const stored = readStored(email);
    if (!stored) throw new Error(tr('Для цього облікового запису Passkey не налаштовано на цьому пристрої.', 'A passkey is not set up for this account on this device.'));
    const secret = await evaluatePrf(unb64(stored.credentialId), unb64(stored.prfSalt));
    try {
        return await unwrapPassphrase(new Uint8Array(secret), stored.wrap);
    } catch {
        // The PRF secret did not decrypt the blob — the enrolment is unusable
        // (e.g. authenticator reset). Drop it so the UI falls back to passphrase.
        removeVaultWebAuthn(email);
        throw new Error(tr('Збережене Passkey-розблокування більше не дійсне. Введіть Vault Passphrase.', 'The saved passkey unlock is no longer valid. Enter your Vault passphrase.'));
    }
}
