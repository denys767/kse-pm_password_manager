import Keycloak from 'keycloak-js';
import { api, setAuthHeaderProvider } from './api';
import * as pmc from './crypto';
import type { FrontendConfig, UserKeysDto } from './types';

export interface VaultKeys {
    kek: CryptoKey;
    privateKey: CryptoKey;
    publicKey: CryptoKey;
}

export interface DevIdentity {
    email: string;
    roles: string;
    groups: string;
}

let keycloak: Keycloak | null = null;

export async function fetchConfig(): Promise<FrontendConfig> {
    return api<FrontendConfig>('/api/config');
}

/**
 * OIDC mode: redirects to Keycloak (Authorization Code + PKCE) if there is no
 * session, then serves fresh bearer tokens to the api() wrapper.
 */
export async function initOidc(config: FrontendConfig): Promise<void> {
    keycloak = new Keycloak({
        url: config.keycloakUrl!,
        realm: config.realm!,
        clientId: config.clientId!,
    });
    await keycloak.init({ onLoad: 'login-required', pkceMethod: 'S256' });
    setAuthHeaderProvider(async () => {
        try {
            await keycloak!.updateToken(30);
        } catch { /* refresh failed — request will 401 and surface an error */ }
        return { Authorization: `Bearer ${keycloak!.token}` };
    });
}

/** Dev mode: identity is whatever the developer types on the unlock screen. */
export function setDevIdentity(identity: DevIdentity): void {
    setAuthHeaderProvider(async () => ({
        'X-Dev-User': identity.email,
        'X-Dev-Roles': identity.roles || 'user',
        'X-Dev-Groups': identity.groups,
    }));
}

/** Full logout: ends the Keycloak SSO session (Epic 4 logout flow). */
export function oidcLogout(): void {
    keycloak?.logout({ redirectUri: window.location.origin });
}

/**
 * First unlock generates the keypair and uploads it (private key encrypted
 * with the KEK); later unlocks download and decrypt it — a wrong passphrase
 * fails AES-GCM authentication and is reported cleanly. Works across devices
 * because the salt and encrypted private key live on the server.
 */
export async function loadOrCreateKeys(passphrase: string): Promise<VaultKeys> {
    let stored: UserKeysDto | null = null;
    try {
        stored = await api<UserKeysDto>('/api/keys/me');
    } catch (e) {
        if ((e as { status?: number }).status !== 404) {
            throw e;
        }
    }
    if (stored === null) {
        // Every new keypair uses Argon2id — see crypto.ts for why.
        const salt = pmc.generateSalt();
        const kek = await pmc.deriveKek(passphrase, salt, 'ARGON2ID');
        const keypair = await pmc.generateUserKeypair();
        const encPriv = await pmc.exportEncryptedPrivateKey(keypair.privateKey, kek);
        const publicKeyB64 = await pmc.exportPublicKey(keypair.publicKey);
        await api('/api/keys/me', {
            method: 'PUT',
            body: JSON.stringify({
                publicKey: publicKeyB64,
                encryptedPrivateKey: encPriv.ct,
                privateKeyIv: encPriv.iv,
                kdfSalt: salt,
                kdfAlgorithm: 'ARGON2ID',
            } satisfies UserKeysDto),
        });
        return { kek, privateKey: keypair.privateKey, publicKey: await pmc.importPublicKey(publicKeyB64) };
    }
    // Existing keypairs keep unlocking with whichever KDF they were registered
    // with — there is no forced migration (see crypto.ts).
    const kek = await pmc.deriveKek(passphrase, stored.kdfSalt, stored.kdfAlgorithm);
    let privateKey: CryptoKey;
    try {
        privateKey = await pmc.importEncryptedPrivateKey(stored.encryptedPrivateKey, stored.privateKeyIv, kek);
    } catch {
        throw new Error('Невірний passphrase для цього vault.');
    }
    return { kek, privateKey, publicKey: await pmc.importPublicKey(stored.publicKey) };
}
