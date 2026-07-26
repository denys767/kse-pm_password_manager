import * as pmc from './crypto';
import { tr } from './i18n';
import type { SecretPayload } from './payload';
import type { SecretType } from './types';

/** Plaintext exists only while the sender or recipient has this page open. */
export interface ExternalShareSnapshot {
    version: 1;
    name: string;
    url: string;
    username: string;
    tags: string;
    type: SecretType;
    password: string;
    payload: SecretPayload;
}

/**
 * Mirrors ExternalShareDtos.MAX_ENCRYPTED_PACKAGE_CHARS. Checking it here turns
 * a bare 400 arriving after the browser has already encrypted everything into a
 * message that says which record is too big and what to do about it.
 */
export const MAX_ENCRYPTED_PACKAGE_CHARS = 1_000_000;

export const encryptShareSnapshot = (snapshot: ExternalShareSnapshot) => pmc.encryptExternalShare(snapshot);

export async function decryptShareSnapshot(fragmentKey: string, encryptedPackage: string,
                                           packageIv: string): Promise<ExternalShareSnapshot> {
    const result = await pmc.decryptExternalShare<ExternalShareSnapshot>(fragmentKey, encryptedPackage, packageIv);
    if (result.version !== 1 || !result.name || !result.type || !result.payload) {
        throw new Error(tr('Непідтримуваний або пошкоджений пакет.', 'Unsupported or corrupted package.'));
    }
    return result;
}
