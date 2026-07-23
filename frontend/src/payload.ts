/**
 * Template-specific secrets are serialized before AES-GCM encryption. This
 * module deliberately has no API calls: plaintext payloads exist only inside
 * the browser process.
 */
import type { SecretType } from './types';

export interface SecretPayload {
    version: 1;
    notes: string;
    apiKey: string;
    apiSecret: string;
    sshPrivateKey: string;
    sshPublicKey: string;
    databaseType: string;
    databaseHost: string;
    databasePort: string;
    databaseName: string;
    databaseUsername: string;
    databasePassword: string;
    cardNumber: string;
    cardCvv: string;
    cardHolder: string;
    cardExpiry: string;
    totpSeed: string;
}

export const emptyPayload = (): SecretPayload => ({
    version: 1, notes: '', apiKey: '', apiSecret: '', sshPrivateKey: '', sshPublicKey: '',
    databaseType: '', databaseHost: '', databasePort: '', databaseName: '', databaseUsername: '', databasePassword: '',
    cardNumber: '', cardCvv: '', cardHolder: '', cardExpiry: '', totpSeed: '',
});

/** Legacy encrypted_notes held just freeform notes. Keep those records readable. */
export function parsePayload(text: string): SecretPayload {
    try {
        const parsed = JSON.parse(text) as Partial<SecretPayload>;
        if (parsed.version === 1) {
            return { ...emptyPayload(), ...parsed, version: 1 };
        }
    } catch { /* legacy note */ }
    return { ...emptyPayload(), notes: text };
}

export function serializePayload(payload: SecretPayload): string {
    return JSON.stringify(payload);
}

export function primarySecretLabel(type: SecretType): string {
    return type === 'API_CREDENTIALS' ? 'API token' : type === 'SSH_KEY' ? 'Passphrase ключа'
        : type === 'DATABASE' ? 'Пароль бази даних'
        : type === 'CARD' ? 'PIN / додатковий секрет' : type === 'SECURE_NOTE' ? 'Додатковий секрет' : 'Пароль';
}
