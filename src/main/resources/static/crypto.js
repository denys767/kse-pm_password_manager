/*
 * PMCrypto — portable client-side crypto for the KSE password manager.
 *
 * Pure WebCrypto functions, no DOM access: designed to move to a TypeScript
 * module unchanged when the frontend migrates to React (roadmap Phase 2).
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

const PMCrypto = (() => {
    const te = new TextEncoder();
    const td = new TextDecoder();

    const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
    const unb64 = (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0));

    const PBKDF2_ITERATIONS = 210000;
    const RSA_PARAMS = {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
    };

    function generateSalt() {
        return b64(crypto.getRandomValues(new Uint8Array(16)));
    }

    async function deriveKek(passphrase, saltB64) {
        const material = await crypto.subtle.importKey(
            'raw', te.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: unb64(saltB64), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
            material,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']);
    }

    async function aesEncrypt(key, bytes) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes);
        return { ct: b64(ct), iv: b64(iv) };
    }

    async function aesDecrypt(key, ctB64, ivB64) {
        return crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(ivB64) }, key, unb64(ctB64));
    }

    // ------------------------------------------------------- user keypair ---

    async function generateUserKeypair() {
        return crypto.subtle.generateKey(RSA_PARAMS, true, ['encrypt', 'decrypt']);
    }

    async function exportPublicKey(publicKey) {
        return b64(await crypto.subtle.exportKey('spki', publicKey));
    }

    async function importPublicKey(spkiB64) {
        return crypto.subtle.importKey(
            'spki', unb64(spkiB64), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    }

    /** PKCS8-export the private key and encrypt it with the KEK for upload. */
    async function exportEncryptedPrivateKey(privateKey, kek) {
        const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
        return aesEncrypt(kek, pkcs8);
    }

    /** Decrypt + import the private key; throws if the KEK (passphrase) is wrong. */
    async function importEncryptedPrivateKey(ctB64, ivB64, kek) {
        const pkcs8 = await aesDecrypt(kek, ctB64, ivB64);
        return crypto.subtle.importKey(
            'pkcs8', pkcs8, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    }

    // ----------------------------------------------------------- item key ---

    async function generateItemKey() {
        return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true,
            ['encrypt', 'decrypt']);
    }

    async function wrapItemKey(itemKey, recipientPublicKey) {
        const raw = await crypto.subtle.exportKey('raw', itemKey);
        return b64(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, recipientPublicKey, raw));
    }

    async function unwrapItemKey(wrappedB64, privateKey) {
        const raw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, unb64(wrappedB64));
        return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true,
            ['encrypt', 'decrypt']);
    }

    /** KEK-wrapping is used for local-only items, where no RSA is involved. */
    async function wrapItemKeyWithKek(itemKey, kek) {
        const raw = await crypto.subtle.exportKey('raw', itemKey);
        return aesEncrypt(kek, raw);
    }

    async function unwrapItemKeyWithKek(ctB64, ivB64, kek) {
        const raw = await aesDecrypt(kek, ctB64, ivB64);
        return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true,
            ['encrypt', 'decrypt']);
    }

    // -------------------------------------------------------- item fields ---

    async function encryptField(itemKey, text) {
        return aesEncrypt(itemKey, te.encode(text));
    }

    async function decryptField(itemKey, ctB64, ivB64) {
        return td.decode(await aesDecrypt(itemKey, ctB64, ivB64));
    }

    return {
        generateSalt,
        deriveKek,
        generateUserKeypair,
        exportPublicKey,
        importPublicKey,
        exportEncryptedPrivateKey,
        importEncryptedPrivateKey,
        generateItemKey,
        wrapItemKey,
        unwrapItemKey,
        wrapItemKeyWithKek,
        unwrapItemKeyWithKek,
        encryptField,
        decryptField,
    };
})();
