/** Mirrors frontend/src/payload.ts — kept minimal since the extension only ever touches totpSeed. */
export interface SecretPayload {
    version: 1;
    notes: string;
    apiKey: string;
    apiSecret: string;
    sshPrivateKey: string;
    cardNumber: string;
    cardCvv: string;
    cardHolder: string;
    cardExpiry: string;
    totpSeed: string;
}

export const emptyPayload = (): SecretPayload => ({
    version: 1, notes: '', apiKey: '', apiSecret: '', sshPrivateKey: '',
    cardNumber: '', cardCvv: '', cardHolder: '', cardExpiry: '', totpSeed: '',
});

export function parsePayload(text: string): SecretPayload {
    try {
        const parsed = JSON.parse(text) as Partial<SecretPayload>;
        if (parsed.version === 1) {
            return { ...emptyPayload(), ...parsed, version: 1 };
        }
    } catch { /* legacy plaintext note */ }
    return { ...emptyPayload(), notes: text };
}

export function serializePayload(payload: SecretPayload): string {
    return JSON.stringify(payload);
}
