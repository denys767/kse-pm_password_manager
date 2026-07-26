/*
 * Copied from frontend/src/crypto.ts (T4 extension MVP).
 * Keep this implementation cryptographically compatible with the web client:
 * KEK -> encrypted RSA private key -> direct/collection item keys.
 */
import { argon2id } from 'hash-wasm';

export interface Encrypted { ct: string; iv: string; }
export type KdfAlgorithm = 'PBKDF2' | 'ARGON2ID';
const te = new TextEncoder();
const td = new TextDecoder();
const b64 = (buf: ArrayBuffer | Uint8Array): string => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (str: string): Uint8Array<ArrayBuffer> => {
    const raw = atob(str); const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    return bytes;
};
const PBKDF2_ITERATIONS = 210000;
const ARGON2ID_MEMORY_KIB = 19456;
const ARGON2ID_ITERATIONS = 2;
const ARGON2ID_PARALLELISM = 1;

async function deriveKekPbkdf2(passphrase: string, saltB64: string): Promise<Uint8Array<ArrayBuffer>> {
    const material = await crypto.subtle.importKey('raw', te.encode(passphrase), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: unb64(saltB64), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, material, 256);
    return new Uint8Array(bits);
}
async function deriveKekArgon2id(passphrase: string, saltB64: string): Promise<Uint8Array<ArrayBuffer>> {
    const raw = await argon2id({ password: passphrase, salt: unb64(saltB64), iterations: ARGON2ID_ITERATIONS, parallelism: ARGON2ID_PARALLELISM, memorySize: ARGON2ID_MEMORY_KIB, hashLength: 32, outputType: 'binary' });
    return new Uint8Array(raw);
}

/**
 * The KEK as raw bytes rather than an opaque CryptoKey.
 *
 * <p>An MV3 service worker is evicted after seconds of idleness, taking every
 * in-memory key with it, and re-deriving costs an Argon2id pass (or 210k
 * PBKDF2 rounds) — which is why the extension used to demand the passphrase
 * again every few minutes. Keeping these bytes in chrome.storage.session
 * (memory-only, never written to disk, cleared when the browser closes) makes
 * waking up free. They are the crown jewels while they are there, which is why
 * they go nowhere near storage.local and why the auto-lock alarm deletes them.
 */
export async function deriveKekBytes(passphrase: string, saltB64: string, algorithm: KdfAlgorithm): Promise<Uint8Array<ArrayBuffer>> {
    if (algorithm === 'PBKDF2') return deriveKekPbkdf2(passphrase, saltB64);
    if (algorithm === 'ARGON2ID') return deriveKekArgon2id(passphrase, saltB64);
    throw new Error(`Unknown KDF algorithm: ${algorithm}`);
}
export async function importKek(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
export async function deriveKek(passphrase: string, saltB64: string, algorithm: KdfAlgorithm): Promise<CryptoKey> {
    return importKek(await deriveKekBytes(passphrase, saltB64, algorithm));
}
export const toBase64 = b64;
export const fromBase64 = unb64;
async function aesDecrypt(key: CryptoKey, ctB64: string, ivB64: string): Promise<ArrayBuffer> {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(ivB64) }, key, unb64(ctB64));
}
export async function importPublicKey(spkiB64: string): Promise<CryptoKey> { return crypto.subtle.importKey('spki', unb64(spkiB64), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']); }
export async function importEncryptedPrivateKey(ctB64: string, ivB64: string, kek: CryptoKey): Promise<CryptoKey> {
    return crypto.subtle.importKey('pkcs8', await aesDecrypt(kek, ctB64, ivB64), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
}
export async function unwrapItemKey(wrappedB64: string, privateKey: CryptoKey): Promise<CryptoKey> {
    const raw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, unb64(wrappedB64));
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
}
export async function unwrapItemKeyWithKek(ctB64: string, ivB64: string, kek: CryptoKey): Promise<CryptoKey> {
    return crypto.subtle.importKey('raw', await aesDecrypt(kek, ctB64, ivB64), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
}
export async function decryptField(itemKey: CryptoKey, ctB64: string, ivB64: string): Promise<string> { return td.decode(await aesDecrypt(itemKey, ctB64, ivB64)); }
export async function encryptField(itemKey: CryptoKey, plaintext: string): Promise<Encrypted> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, itemKey, te.encode(plaintext));
    return { ct: b64(ct), iv: b64(iv) };
}
export async function generateItemKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
export async function wrapItemKey(itemKey: CryptoKey, publicKey: CryptoKey): Promise<string> {
    const raw = await crypto.subtle.exportKey('raw', itemKey);
    return b64(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, raw));
}

// ------------------------------------------------------------------ TOTP ---

/** Same RFC 6238 implementation as frontend/src/crypto.ts — kept in sync manually. */
export function decodeTotpSeed(seedOrUri: string): Uint8Array<ArrayBuffer> {
    let seed = seedOrUri.trim();
    if (seed.toLowerCase().startsWith('otpauth://')) {
        try { seed = new URL(seed).searchParams.get('secret') ?? ''; } catch { seed = ''; }
    }
    seed = seed.replace(/[\s-]/g, '').replace(/=+$/, '').toUpperCase();
    if (!seed || !/^[A-Z2-7]+$/.test(seed)) {
        throw new Error('TOTP seed має бути Base32 або otpauth URI.');
    }
    let bits = 0; let value = 0;
    const bytes: number[] = [];
    for (const character of seed) {
        value = (value << 5) | 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(character);
        bits += 5;
        if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
    }
    return new Uint8Array(bytes);
}
export async function generateTotp(seedOrUri: string, timestamp = Date.now()): Promise<string> {
    const key = await crypto.subtle.importKey('raw', decodeTotpSeed(seedOrUri), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const counter = Math.floor(timestamp / 30_000);
    const message = new Uint8Array(8);
    let remaining = counter;
    for (let i = 7; i >= 0; i--) { message[i] = remaining & 0xff; remaining = Math.floor(remaining / 256); }
    const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, message));
    const offset = mac[mac.length - 1] & 0x0f;
    const value = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
    return String(value % 1_000_000).padStart(6, '0');
}
