import * as pmc from './crypto';
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

export const encryptShareSnapshot = (snapshot: ExternalShareSnapshot) => pmc.encryptExternalShare(snapshot);

export async function decryptShareSnapshot(fragmentKey: string, encryptedPackage: string,
                                           packageIv: string): Promise<ExternalShareSnapshot> {
    const result = await pmc.decryptExternalShare<ExternalShareSnapshot>(fragmentKey, encryptedPackage, packageIv);
    if (result.version !== 1 || !result.name || !result.type || !result.payload) {
        throw new Error('Непідтримуваний або пошкоджений пакет.');
    }
    return result;
}
