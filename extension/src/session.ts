/**
 * What survives a service-worker eviction, and nothing more.
 *
 * MV3 tears the background worker down after seconds of idleness. Every
 * module-level variable goes with it, which is why signing in and unlocking
 * used to evaporate several times an hour: the OIDC token was gone, the vault
 * keys were gone, and the only recovery on offer was to type the passphrase
 * again.
 *
 * `chrome.storage.session` is the right home for this. It lives in memory, is
 * never written to disk, and is dropped when the browser closes — so the vault
 * is locked again by the next browser start, exactly as a password manager
 * should behave, but a background restart thirty seconds after you unlocked it
 * costs nothing. `storage.local` would survive reboots too, and would mean
 * writing key material to disk; that is not a trade we make.
 */

export interface StoredSession {
    /** OIDC. Access tokens are short-lived, so the refresh token is the part that matters. */
    accessToken?: string;
    refreshToken?: string;
    /** Vault, present only while unlocked. */
    kek?: string;
    encryptedPrivateKey?: string;
    privateKeyIv?: string;
    publicKey?: string;
    /** Drives the idle auto-lock; refreshed on every deliberate use of the vault. */
    lastUsedAt?: number;
}

const KEY = 'pm.session';

let accessLevelSet = false;
async function ready(): Promise<void> {
    if (accessLevelSet) return;
    accessLevelSet = true;
    // Content scripts run in pages we do not control. They have no business
    // reading vault key material, and the default access level would let them.
    try { await chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' }); }
    catch { /* already set, or a Chrome build without it — the default is TRUSTED_CONTEXTS anyway */ }
}

export async function readSession(): Promise<StoredSession> {
    await ready();
    const stored = await chrome.storage.session.get(KEY) as Record<string, StoredSession | undefined>;
    return stored[KEY] ?? {};
}

export async function patchSession(patch: Partial<StoredSession>): Promise<void> {
    await ready();
    await chrome.storage.session.set({ [KEY]: { ...(await readSession()), ...patch } });
}

export async function clearSession(): Promise<void> {
    await ready();
    await chrome.storage.session.remove(KEY);
}

/** Drops the vault half while leaving the sign-in intact: locking must not
 * make the user authenticate to Keycloak again, only re-enter the passphrase. */
export async function clearVaultFromSession(): Promise<void> {
    const { accessToken, refreshToken } = await readSession();
    await ready();
    await chrome.storage.session.set({ [KEY]: { accessToken, refreshToken } });
}
