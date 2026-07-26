import type { Encrypted, KdfAlgorithm } from './crypto';

export interface FrontendConfig {
    authMode: 'oidc' | 'dev-headers';
    keycloakUrl?: string;
    realm?: string;
    clientId?: string;
    /** The KSE Password Manager browser extension's fixed ID, used to reach it
     *  via chrome.runtime.connect for the passkey-unlock bridge. */
    extensionId?: string;
}

export interface Me {
    email: string;
    displayName: string;
    roles: string[];
    groups: string[];
}

export type ItemType = 'PERSONAL' | 'SHARED';
export type SecretType = 'LOGIN' | 'API_CREDENTIALS' | 'SSH_KEY' | 'DATABASE' | 'CARD' | 'SECURE_NOTE';
export type SyncMode = 'SERVER_SYNCED' | 'LOCAL_ONLY';
export type AccessRole = 'NONE' | 'VIEWER' | 'EDITOR' | 'AUTOFILL_ONLY' | 'PASSKEY_ONLY' | 'OWNER';

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
    type: SecretType;
    itemType: ItemType;
    syncMode: SyncMode;
    accessRole: AccessRole | null;
    wrappedKey: string | null;
    collectionId: string | null;
    collectionWrappedKey: string | null;
    collectionWrappedKeyIv: string | null;
    updatedAt: string;
    /** Opaque, client-encrypted attachment metadata. Local-only items never have one. */
    attachment?: AttachmentMetadata | null;
    /** Present only on local-only items (stored in localStorage). */
    kekWrappedKey?: Encrypted;
}

export interface AttachmentMetadata {
    id: string;
    encryptedFilename: string;
    encryptedFilenameIv: string;
    mimeType: string;
    ciphertextSize: number;
    ciphertextSha256: string;
    nonce: string;
    wrappedFileKey: string;
    wrappedFileKeyIv: string;
}

export type CollectionRole = 'VIEWER' | 'EDITOR' | 'MANAGER';
export type CollectionMemberStatus = 'ACTIVE' | 'PENDING_PROVISIONING' | 'PENDING_REMOVAL';

export interface Collection {
    id: string;
    name: string;
    ownerEmail: string;
    directoryGroup: string | null;
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
    role: 'VIEWER' | 'EDITOR' | 'AUTOFILL_ONLY' | 'PASSKEY_ONLY';
    grantedBy: string;
    createdAt: string;
    status?: 'ACTIVE' | 'RELINK_REQUIRED' | 'REVOKED';
    directorySubjectId?: string | null;
    directoryDisplayName?: string | null;
    warning?: string;
    /** Only present for GROUP grantees: whether workspace governance currently
     * marks this group visible to non-admin users. */
    groupVisibleToUsers?: boolean | null;
}

export interface DirectoryPrincipal {
    type: 'USER' | 'GROUP';
    id: string;
    email: string;
    displayName: string;
    vaultKeyAvailable: boolean;
    memberCount: number | null;
    /** Meaningless for USER (always true). For GROUP, false means the group
     * is hidden by workspace governance — only admins receive it at all. */
    visibleToUsers: boolean;
    /** Google Workspace profile photo as a data: URI; null for groups and for
     *  users without one. */
    avatarDataUrl: string | null;
}

export interface PermissionMemberInfo {
    id: string;
    memberEmail: string;
    status: 'PENDING_PROVISIONING' | 'ACTIVE' | 'PENDING_REMOVAL';
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
    /** The Google Workspace profile photo, synced by the directory job.
     *  Read-only: there is no manual upload. */
    avatarDataUrl: string | null;
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

export interface AuditPage {
    content: AuditEvent[];
    page: number;
    size: number;
    totalElements: number;
    totalPages: number;
}

export interface WorkspaceUser {
    email: string;
    directoryId: string;
    displayName: string;
    googleAdmin: boolean;
    roleOverride: 'ADMIN' | 'USER' | null;
    status: 'ACTIVE' | 'SUSPENDED' | 'REVOKED';
    syncedAt: string;
}

export interface WorkspaceGroup {
    email: string;
    directoryId: string;
    displayName: string;
    visibleToUsers: boolean;
    syncedAt: string;
}

/** Deliberately excludes all ciphertext, keys, and attachment data. */
export interface AdminRecordMetadata {
    id: string;
    name: string;
    ownerEmail: string;
    type: SecretType;
    itemType: ItemType;
    syncMode: SyncMode;
    createdAt: string;
    updatedAt: string;
}

/** Metadata only: this endpoint never exposes any item ciphertext or keys. */
export interface AdminTagSummary {
    name: string;
    usageCount: number;
}

/** Freshness of the local Google Workspace snapshot (admin only). Null
 * timestamps mean the directory has never been read successfully. */
export interface DirectoryStatus {
    lastSuccessAt: string | null;
    lastAttemptAt: string | null;
    lastError: string | null;
    consecutiveFailures: number;
    knownUsers: number;
    /** Credential source, and whether it can keep working without a human
     * re-authenticating (a gcloud user credential cannot). */
    credentialMode: string;
    credentialUnattended: boolean;
    credentialDetail: string;
    credentialError: string | null;
    /** Set while directory lookups are being answered from the local snapshot
     * because Google is unreachable. */
    servingFromSnapshotSince: string | null;
}
