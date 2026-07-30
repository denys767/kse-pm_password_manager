import type { Encrypted, KdfAlgorithm } from './crypto';
export interface FrontendConfig { authMode: 'oidc'; keycloakUrl: string; realm: string; clientId: string; }
export interface UserKeysDto { publicKey: string; encryptedPrivateKey: string; privateKeyIv: string; kdfSalt: string; kdfAlgorithm: KdfAlgorithm; }
export interface PasswordItem {
    id: string; name: string; url: string | null; username: string | null;
    encryptedPassword: string; passwordIv: string;
    encryptedNotes: string | null; notesIv: string | null;
    tags: string | null; type: string | null; itemType: 'PERSONAL' | 'SHARED';
    syncMode: 'SERVER_SYNCED' | 'LOCAL_ONLY';
    accessRole?: 'VIEWER' | 'EDITOR' | 'AUTOFILL_ONLY' | 'PASSKEY_ONLY' | 'OWNER';
    wrappedKey: string | null; collectionId: string | null;
    collectionWrappedKey: string | null; collectionWrappedKeyIv: string | null;
    kekWrappedKey?: Encrypted;
}
export interface Collection { id: string; myWrappedKey: string; }
export interface Settings { clipboardClearSeconds: number; defaultSyncMode: 'SERVER_SYNCED' | 'LOCAL_ONLY'; }
/** One credential whose grantees are still missing a wrapped key; see
 * PasskeyService.pendingKeyDistribution. */
export interface KeyDistribution {
    id: string; itemId: string; itemName: string; relyingPartyId: string;
    wrappedCredentialKeyForMe: string;
    pending: Array<{ email: string; publicKey: string }>;
}
/** What the in-page picker is allowed to know about a match. */
export interface AutofillCandidate { id: string; name: string; username: string; }
/** Response to 'autofill-candidates'. While the vault is locked, `candidates`
 * is always empty — only `hasMatch` (no account names) is disclosed. */
export interface AutofillCandidatesResult { locked: boolean; hasMatch: boolean; candidates: AutofillCandidate[]; }
export interface PasskeyCredential {
    id: string; itemId: string; relyingPartyId: string; credentialId: string; userHandle: string;
    algorithm: 'ES256'; publicKey: string; encryptedPrivateMaterial: string; privateMaterialIv: string;
    transports: string | null; signCounter: number; wrappedCredentialKey: string;
}
