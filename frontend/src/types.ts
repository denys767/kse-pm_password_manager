import type { Encrypted, KdfAlgorithm } from './crypto';

export interface FrontendConfig {
    authMode: 'oidc' | 'dev-headers';
    keycloakUrl?: string;
    realm?: string;
    clientId?: string;
}

export interface Me {
    email: string;
    displayName: string;
    roles: string[];
    groups: string[];
}

export type ItemType = 'PERSONAL' | 'SHARED';
export type SyncMode = 'SERVER_SYNCED' | 'LOCAL_ONLY';
export type AccessRole = 'NONE' | 'VIEWER' | 'EDITOR' | 'OWNER';

export interface PasswordItem {
    id: string;
    name: string;
    url: string | null;
    username: string | null;
    encryptedPassword: string;
    passwordIv: string;
    encryptedNotes: string | null;
    notesIv: string | null;
    tags: string | null;
    ownerEmail: string;
    itemType: ItemType;
    syncMode: SyncMode;
    accessRole: AccessRole | null;
    wrappedKey: string | null;
    collectionId: string | null;
    collectionWrappedKey: string | null;
    collectionWrappedKeyIv: string | null;
    updatedAt: string;
    /** Present only on local-only items (stored in localStorage). */
    kekWrappedKey?: Encrypted;
}

export type CollectionRole = 'VIEWER' | 'EDITOR' | 'MANAGER';
export type CollectionMemberStatus = 'ACTIVE' | 'PENDING_PROVISIONING' | 'PENDING_REMOVAL';

export interface Collection {
    id: string;
    name: string;
    ownerEmail: string;
    keycloakGroup: string | null;
    myRole: CollectionRole;
    /** Collection key wrapped with my public key. */
    myWrappedKey: string;
    memberCount: number;
    pendingProvisioningCount: number;
    pendingRemovalCount: number;
    createdAt: string;
}

export interface CollectionMemberInfo {
    id: string;
    memberEmail: string;
    role: CollectionRole;
    status: CollectionMemberStatus;
    addedBy: string;
    createdAt: string;
}

export interface Permission {
    id: string;
    granteeType: 'USER' | 'GROUP';
    grantee: string;
    role: 'VIEWER' | 'EDITOR';
    grantedBy: string;
    createdAt: string;
    warning?: string;
}

export interface UserKeysDto {
    email?: string;
    publicKey: string;
    encryptedPrivateKey: string;
    privateKeyIv: string;
    kdfSalt: string;
    kdfAlgorithm: KdfAlgorithm;
}

export interface Settings {
    defaultSyncMode: SyncMode;
    clipboardClearSeconds: number;
}

export interface ItemVersion {
    id: string;
    name: string;
    url: string | null;
    username: string | null;
    encryptedPassword: string;
    passwordIv: string;
    encryptedNotes: string | null;
    notesIv: string | null;
    replacedBy: string;
    replacedAt: string;
}

export interface Anomaly {
    actorEmail: string;
    action: string;
    count: number;
    windowMinutes: number;
    threshold: number;
}

export interface AuditEvent {
    id: number;
    occurredAt: string;
    actorEmail: string;
    action: string;
    itemId: string | null;
    itemName: string | null;
    target: string | null;
    details: string | null;
}
