/*
 * Client-side crypto for the KSE password manager (TypeScript port of the
 * Phase 1 crypto.js — logic unchanged).
 *
 * Model (Bitwarden-style E2E):
 *  - KEK: AES-256 derived from the vault passphrase. New keypairs use
 *    Argon2id (memory-hard, OWASP-recommended — resists GPU/ASIC brute force
 *    far better than PBKDF2 at the same wall-clock unlock time); PBKDF2 is
 *    kept only to keep unlocking keypairs registered before Argon2id existed
 *    (see kdfAlgorithm on UserKeys — there is no forced migration, since
 *    re-deriving requires the user's passphrase, which the server never has).
 *    Never leaves the browser.
 *  - User keypair: RSA-OAEP-2048. Public key (SPKI) is stored in the clear;
 *    private key (PKCS8) is AES-GCM-encrypted with the KEK before upload.
 *  - Item key: random AES-256 per vault item; encrypts the password/notes
 *    fields (AES-GCM, fresh IV per field). Stored only wrapped: RSA-OAEP with
 *    each recipient's public key (server items) or AES-GCM with the KEK
 *    (local-only items).
 */
import { argon2id } from 'hash-wasm';

export interface Encrypted {
    ct: string;
    iv: string;
}

export type KdfAlgorithm = 'PBKDF2' | 'ARGON2ID';

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
// OWASP's second recommendation for Argon2id — tuned for constrained
// environments (a browser tab competing for CPU/memory) rather than a
// dedicated server: m=19 MiB, t=2, p=1.
const ARGON2ID_MEMORY_KIB = 19456;
const ARGON2ID_ITERATIONS = 2;
const ARGON2ID_PARALLELISM = 1;
const RSA_PARAMS: RsaHashedKeyGenParams = {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
};

export function generateSalt(): string {
    return b64(crypto.getRandomValues(new Uint8Array(16)));
}

async function deriveKekPbkdf2(passphrase: string, saltB64: string): Promise<CryptoKey> {
    const material = await crypto.subtle.importKey(
        'raw', te.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: unb64(saltB64), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']);
}

async function deriveKekArgon2id(passphrase: string, saltB64: string): Promise<CryptoKey> {
    const raw = await argon2id({
        password: passphrase,
        salt: unb64(saltB64),
        iterations: ARGON2ID_ITERATIONS,
        parallelism: ARGON2ID_PARALLELISM,
        memorySize: ARGON2ID_MEMORY_KIB,
        hashLength: 32,
        outputType: 'binary',
    });
    // Same ArrayBuffer<->ArrayBufferLike coercion as unb64: hash-wasm's return
    // type isn't narrowed to Uint8Array<ArrayBuffer>, which BufferSource-typed
    // WebCrypto APIs require under TS 5.7+.
    return crypto.subtle.importKey('raw', new Uint8Array(raw), { name: 'AES-GCM' }, false,
        ['encrypt', 'decrypt']);
}

/** Dispatches to the KDF the keypair was actually registered with — fails
 * closed on an unrecognized value rather than silently falling back. */
export async function deriveKek(
    passphrase: string, saltB64: string, algorithm: KdfAlgorithm): Promise<CryptoKey> {
    switch (algorithm) {
        case 'ARGON2ID':
            return deriveKekArgon2id(passphrase, saltB64);
        case 'PBKDF2':
            return deriveKekPbkdf2(passphrase, saltB64);
        default:
            throw new Error(`Unknown KDF algorithm: ${algorithm}`);
    }
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

/** Encrypts a self-contained external snapshot with a fresh AES-256 key.
 * The returned key is URL-fragment material only: callers must not send or
 * persist it. */
export async function encryptExternalShare(snapshot: unknown): Promise<{
    encryptedPackage: string; packageIv: string; fragmentKey: string;
}> {
    const key = await generateItemKey();
    const encrypted = await aesEncrypt(key, te.encode(JSON.stringify(snapshot)));
    return {
        encryptedPackage: encrypted.ct,
        packageIv: encrypted.iv,
        fragmentKey: b64(await crypto.subtle.exportKey('raw', key)),
    };
}

/** Imports the fragment-only key just long enough to decrypt a public package. */
export async function decryptExternalShare<T>(fragmentKey: string, encryptedPackage: string,
                                              packageIv: string): Promise<T> {
    const key = await crypto.subtle.importKey('raw', unb64(fragmentKey), { name: 'AES-GCM' }, false,
        ['decrypt']);
    return JSON.parse(td.decode(await aesDecrypt(key, encryptedPackage, packageIv))) as T;
}

// ------------------------------------------------------------------ TOTP ---

/** Decode a Base32 seed locally. Accepts a copied otpauth URI as a convenience. */
export function decodeTotpSeed(seedOrUri: string): Uint8Array<ArrayBuffer> {
    let seed = seedOrUri.trim();
    if (seed.toLowerCase().startsWith('otpauth://')) {
        try {
            seed = new URL(seed).searchParams.get('secret') ?? '';
        } catch {
            seed = '';
        }
    }
    seed = seed.replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();
    if (!seed || !/^[A-Z2-7]+$/.test(seed)) {
        throw new Error('TOTP seed має бути Base32 або otpauth URI.');
    }
    let bits = 0;
    let value = 0;
    const bytes: number[] = [];
    for (const character of seed) {
        value = (value << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(character);
        bits += 5;
        if (bits >= 8) {
            bytes.push((value >>> (bits - 8)) & 0xff);
            bits -= 8;
        }
    }
    return new Uint8Array(bytes);
}

/** RFC 6238, HMAC-SHA-1, six digits, 30 second step. Never sends the seed. */
export async function generateTotp(seedOrUri: string, timestamp = Date.now()): Promise<string> {
    const key = await crypto.subtle.importKey('raw', decodeTotpSeed(seedOrUri),
        { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const counter = Math.floor(timestamp / 30_000);
    const message = new Uint8Array(8);
    let remaining = counter;
    for (let i = 7; i >= 0; i--) {
        message[i] = remaining & 0xff;
        remaining = Math.floor(remaining / 256);
    }
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
    const offset = mac[mac.length - 1] & 0x0f;
    const value = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16)
        | (mac[offset + 2] << 8) | mac[offset + 3];
    return String(value % 1_000_000).padStart(6, '0');
}
