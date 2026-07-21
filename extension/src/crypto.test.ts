import { deriveKek, decryptField } from './crypto';
const salt = 'MDEyMzQ1Njc4OWFiY2RlZg==';
async function fixture(algorithm: 'PBKDF2' | 'ARGON2ID'): Promise<void> {
    const key = await deriveKek('correct horse battery staple', salt, algorithm);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(`fixture:${algorithm}`));
    const value = await decryptField(key, btoa(String.fromCharCode(...new Uint8Array(cipher))), btoa(String.fromCharCode(...iv)));
    if (value !== `fixture:${algorithm}`) throw new Error(`${algorithm} decryption fixture failed`);
}
void (async () => {
    await fixture('PBKDF2');
    await fixture('ARGON2ID');
    console.log('crypto fixtures: PBKDF2 and Argon2id passed');
})();
