/*
 * Client-side crypto for the KSE password manager (TypeScript port of the
 * Phase 1 crypto.js — logic unchanged).
 *
 * Model (Bitwarden-style E2E):
 *  - KEK: AES-256 derived from the vault passphrase (PBKDF2-SHA256, 210k
 *    iterations, per-user salt stored server-side). Never leaves the browser.
 *  - User keypair: RSA-OAEP-2048. Public key (SPKI) is stored in the clear;
 *    private key (PKCS8) is AES-GCM-encrypted with the KEK before upload.
 *  - Item key: random AES-256 per vault item; encrypts the password/notes
 *    fields (AES-GCM, fresh IV per field). Stored only wrapped: RSA-OAEP with
 *    each recipient's public key (server items) or AES-GCM with the KEK
 *    (local-only items).
 */

export interface Encrypted {
    ct: string;
    iv: string;
}

const te = new TextEncoder();
const td = new TextDecoder();

const b64 = (buf: ArrayBuffer | Uint8Array): string =>
    btoa(String.fromCharCode(...new Uint8Array(buf as ArrayBuffer)));

// Built explicitly on a fresh ArrayBuffer so TS 5.7+ types it as
// Uint8Array<ArrayBuffer>, which BufferSource-typed WebCrypto APIs require.
const unb64 = (str: string): Uint8Array<ArrayBuffer> => {
    const raw = atob(str);
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) {
        bytes[i] = raw.charCodeAt(i);
    }
    return bytes;
};

const PBKDF2_ITERATIONS = 210000;
const RSA_PARAMS: RsaHashedKeyGenParams = {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
};

export function generateSalt(): string {
    return b64(crypto.getRandomValues(new Uint8Array(16)));
}

export async function deriveKek(passphrase: string, saltB64: string): Promise<CryptoKey> {
    const material = await crypto.subtle.importKey(
        'raw', te.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: unb64(saltB64), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']);
}

async function aesEncrypt(key: CryptoKey, bytes: BufferSource): Promise<Encrypted> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
    return { ct: b64(ct), iv: b64(iv) };
}

async function aesDecrypt(key: CryptoKey, ctB64: string, ivB64: string): Promise<ArrayBuffer> {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(ivB64) }, key, unb64(ctB64));
}

// ----------------------------------------------------------- user keypair ---

export async function generateUserKeypair(): Promise<CryptoKeyPair> {
    return crypto.subtle.generateKey(RSA_PARAMS, true, ['encrypt', 'decrypt']);
}

export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
    return b64(await crypto.subtle.exportKey('spki', publicKey));
}

export async function importPublicKey(spkiB64: string): Promise<CryptoKey> {
    return crypto.subtle.importKey(
        'spki', unb64(spkiB64), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
}

/** PKCS8-export the private key and encrypt it with the KEK for upload. */
export async function exportEncryptedPrivateKey(privateKey: CryptoKey, kek: CryptoKey): Promise<Encrypted> {
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
    return aesEncrypt(kek, pkcs8);
}

/** Decrypt + import the private key; throws if the KEK (passphrase) is wrong. */
export async function importEncryptedPrivateKey(
    ctB64: string, ivB64: string, kek: CryptoKey): Promise<CryptoKey> {
    const pkcs8 = await aesDecrypt(kek, ctB64, ivB64);
    return crypto.subtle.importKey(
        'pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
}

// --------------------------------------------------------------- item key ---

export async function generateItemKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true,
        ['encrypt', 'decrypt']);
}

export async function wrapItemKey(itemKey: CryptoKey, recipientPublicKey: CryptoKey): Promise<string> {
    const raw = await crypto.subtle.exportKey('raw', itemKey);
    return b64(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, recipientPublicKey, raw));
}

export async function unwrapItemKey(wrappedB64: string, privateKey: CryptoKey): Promise<CryptoKey> {
    const raw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, unb64(wrappedB64));
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
}

/** KEK-wrapping is used for local-only items, where no RSA is involved. */
export async function wrapItemKeyWithKek(itemKey: CryptoKey, kek: CryptoKey): Promise<Encrypted> {
    const raw = await crypto.subtle.exportKey('raw', itemKey);
    return aesEncrypt(kek, raw);
}

export async function unwrapItemKeyWithKek(
    ctB64: string, ivB64: string, kek: CryptoKey): Promise<CryptoKey> {
    const raw = await aesDecrypt(kek, ctB64, ivB64);
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
}

// ------------------------------------------------------------ item fields ---

export async function encryptField(itemKey: CryptoKey, text: string): Promise<Encrypted> {
    return aesEncrypt(itemKey, te.encode(text));
}

export async function decryptField(itemKey: CryptoKey, ctB64: string, ivB64: string): Promise<string> {
    return td.decode(await aesDecrypt(itemKey, ctB64, ivB64));
}
