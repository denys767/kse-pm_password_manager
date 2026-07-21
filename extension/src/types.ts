import type { Encrypted, KdfAlgorithm } from './crypto';
export interface FrontendConfig { authMode: 'oidc'; keycloakUrl: string; realm: string; clientId: string; }
export interface UserKeysDto { publicKey: string; encryptedPrivateKey: string; privateKeyIv: string; kdfSalt: string; kdfAlgorithm: KdfAlgorithm; }
export interface PasswordItem { id: string; name: string; url: string | null; username: string | null; encryptedPassword: string; passwordIv: string; syncMode: 'SERVER_SYNCED' | 'LOCAL_ONLY'; wrappedKey: string | null; collectionId: string | null; collectionWrappedKey: string | null; collectionWrappedKeyIv: string | null; kekWrappedKey?: Encrypted; }
export interface Collection { id: string; myWrappedKey: string; }
export interface Settings { clipboardClearSeconds: number; }
