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

async function deriveKekPbkdf2(passphrase: string, saltB64: string): Promise<CryptoKey> {
    const material = await crypto.subtle.importKey('raw', te.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: unb64(saltB64), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function deriveKekArgon2id(passphrase: string, saltB64: string): Promise<CryptoKey> {
    const raw = await argon2id({ password: passphrase, salt: unb64(saltB64), iterations: ARGON2ID_ITERATIONS, parallelism: ARGON2ID_PARALLELISM, memorySize: ARGON2ID_MEMORY_KIB, hashLength: 32, outputType: 'binary' });
    return crypto.subtle.importKey('raw', new Uint8Array(raw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
export async function deriveKek(passphrase: string, saltB64: string, algorithm: KdfAlgorithm): Promise<CryptoKey> {
    if (algorithm === 'PBKDF2') return deriveKekPbkdf2(passphrase, saltB64);
    if (algorithm === 'ARGON2ID') return deriveKekArgon2id(passphrase, saltB64);
    throw new Error(`Unknown KDF algorithm: ${algorithm}`);
}
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
