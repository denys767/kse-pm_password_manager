/* Chrome's WebAuthn proxy supplies JSON-compatible public-key options. This
 * module deliberately has no page-content input: RP/origin checks happen before
 * generating or using a vault credential. */
import * as pmc from './crypto';
import { matchesOrigin } from './origin';
import type { PasswordItem } from './types';

export interface StoredPasskey { id: string; itemId: string; relyingPartyId: string; credentialId: string; userHandle: string; algorithm: 'ES256'; publicKey: string; encryptedPrivateMaterial: string; privateMaterialIv: string; transports: string | null; signCounter: number; wrappedCredentialKey: string; }
export interface CreatedPasskey { credentialId: string; publicKey: string; encryptedPrivateMaterial: string; privateMaterialIv: string; wrappedCredentialKey: string; }
const te = new TextEncoder();
const td = new TextDecoder();
export const b64url = (bytes: Uint8Array): string => btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
export const fromB64url = (value: string): Uint8Array => { const raw = atob(value.replaceAll('-', '+').replaceAll('_', '/').padEnd(Math.ceil(value.length / 4) * 4, '=')); return Uint8Array.from(raw, c => c.charCodeAt(0)); };
const u32 = (n: number) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
const concat = (...parts: Uint8Array[]) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let offset = 0; for (const part of parts) { out.set(part, offset); offset += part.length; } return out; };

/** Tiny deterministic CBOR writer for WebAuthn attestation/COSE structures. */
function cborHead(major: number, value: number): Uint8Array { if (value < 24) return new Uint8Array([(major << 5) | value]); if (value < 256) return new Uint8Array([(major << 5) | 24, value]); if (value < 65536) return new Uint8Array([(major << 5) | 25, value >>> 8, value & 255]); return concat(new Uint8Array([(major << 5) | 26]), u32(value)); }
function cbor(value: unknown): Uint8Array {
    if (value instanceof Uint8Array) return concat(cborHead(2, value.length), value);
    if (typeof value === 'string') return concat(cborHead(3, te.encode(value).length), te.encode(value));
    if (typeof value === 'number') return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
    if (Array.isArray(value)) return concat(cborHead(4, value.length), ...value.map(cbor));
    if (value && typeof value === 'object') { const entries = Object.entries(value as Record<string, unknown>); return concat(cborHead(5, entries.length), ...entries.flatMap(([k, v]) => [cbor(/^\d+$/.test(k) ? Number(k) : k), cbor(v)])); }
    throw new Error('Unsupported CBOR value');
}
async function hash(value: string | Uint8Array): Promise<Uint8Array> {
    const bytes = typeof value === 'string' ? te.encode(value) : value;
    const exact = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
    return new Uint8Array(await crypto.subtle.digest('SHA-256', exact));
}
function requireOrigin(options: Record<string, unknown>, rpId: string): string {
    const origin = options.origin;
    if (typeof origin !== 'string') throw new Error('WebAuthn proxy request did not supply an origin; refusing to forge clientDataJSON.');
    const url = new URL(origin);
    if (url.protocol !== 'https:' && url.hostname !== 'localhost') throw new Error('Passkeys require a secure origin.');
    const host = url.hostname.toLowerCase(); const rp = rpId.toLowerCase();
    if (host !== rp && !host.endsWith(`.${rp}`)) throw new Error('RP ID does not match the request origin.');
    return url.origin;
}
function validRpId(value: unknown): string { if (typeof value !== 'string' || !/^(localhost|[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$/i.test(value)) throw new Error('Invalid RP ID.'); return value.toLowerCase(); }
function clientData(type: 'webauthn.create' | 'webauthn.get', challenge: string, origin: string): Uint8Array { if (typeof challenge !== 'string') throw new Error('Missing WebAuthn challenge.'); return te.encode(JSON.stringify({ type, challenge, origin, crossOrigin: false })); }
function jwkCoordinate(value: string | undefined): Uint8Array { if (!value) throw new Error('Invalid P-256 public key.'); return fromB64url(value); }
function cosePublicKey(jwk: JsonWebKey): Uint8Array { return cbor({ 1: 2, 3: -7, '-1': 1, '-2': jwkCoordinate(jwk.x), '-3': jwkCoordinate(jwk.y) }); }
async function authenticatorData(rpId: string, flags: number, counter: number, attested?: { credentialId: Uint8Array; publicKey: JsonWebKey }): Promise<Uint8Array> {
    const base = concat(await hash(rpId), new Uint8Array([flags]), u32(counter));
    if (!attested) return base;
    const aaguid = new Uint8Array(16); const idLength = new Uint8Array([attested.credentialId.length >>> 8, attested.credentialId.length & 255]);
    return concat(base, aaguid, idLength, attested.credentialId, cosePublicKey(attested.publicKey));
}
async function credentialKey(passkey: StoredPasskey, vaultPrivateKey: CryptoKey): Promise<CryptoKey> { return pmc.unwrapItemKey(passkey.wrappedCredentialKey, vaultPrivateKey); }
export async function createMaterial(vaultPublicKey: CryptoKey): Promise<CreatedPasskey> {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as CryptoKeyPair;
    const credentialKey = await pmc.generateItemKey(); const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey); const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const encrypted = await pmc.encryptField(credentialKey, JSON.stringify(privateJwk));
    return { credentialId: b64url(crypto.getRandomValues(new Uint8Array(32))), publicKey: b64url(cosePublicKey(publicJwk)), encryptedPrivateMaterial: encrypted.ct, privateMaterialIv: encrypted.iv, wrappedCredentialKey: await pmc.wrapItemKey(credentialKey, vaultPublicKey) };
}
export async function createResponse(options: Record<string, unknown>, item: PasswordItem, vaultPublicKey: CryptoKey): Promise<{ responseJson: string; payload: CreatedPasskey & { itemId: string; relyingPartyId: string; userHandle: string; transports: string } }> {
    const rp = options.rp as Record<string, unknown>; const user = options.user as Record<string, unknown>; const rpId = validRpId(rp?.id); const origin = requireOrigin(options, rpId);
    if (!item.id || !matchesOrigin(item.url, origin)) throw new Error('Passkey must be attached to a vault item with the exact request origin.');
    const algorithms = (options.pubKeyCredParams as Array<Record<string, unknown>> | undefined) ?? [];
    if (!algorithms.some(p => p.alg === -7 && p.type === 'public-key')) throw new Error('Only ES256 passkeys are supported.');
    if (typeof user?.id !== 'string') throw new Error('Missing WebAuthn user handle.');
    // The COSE public key is saved and reused verbatim for the attested credential
    // data; private material remains encrypted under a freshly generated key.
    const material = await createMaterial(vaultPublicKey);
    const credentialId = fromB64url(material.credentialId); const client = clientData('webauthn.create', options.challenge as string, origin);
    const authData = concat(await hash(rpId), new Uint8Array([0x45]), u32(0), new Uint8Array(16), new Uint8Array([credentialId.length >>> 8, credentialId.length & 255]), credentialId, fromB64url(material.publicKey));
    const attestationObject = cbor({ fmt: 'none', authData, attStmt: {} });
    return { responseJson: JSON.stringify({ id: material.credentialId, rawId: material.credentialId, type: 'public-key', response: { clientDataJSON: b64url(client), attestationObject: b64url(attestationObject) }, clientExtensionResults: {} }), payload: { ...material, itemId: item.id, relyingPartyId: rpId, userHandle: user.id as string, transports: 'internal' } };
}
export async function assertionResponse(options: Record<string, unknown>, passkey: StoredPasskey, vaultPrivateKey: CryptoKey): Promise<{ responseJson: string; nextCounter: number }> {
    const rpId = validRpId(options.rpId); if (rpId !== passkey.relyingPartyId) throw new Error('RP ID mismatch.'); const origin = requireOrigin(options, rpId);
    const allowed = options.allowCredentials as Array<Record<string, unknown>> | undefined;
    if (allowed && allowed.length && !allowed.some(c => c.id === passkey.credentialId && c.type === 'public-key')) throw new Error('Credential is not allowed by this request.');
    const key = await credentialKey(passkey, vaultPrivateKey); const privateJwk = JSON.parse(await pmc.decryptField(key, passkey.encryptedPrivateMaterial, passkey.privateMaterialIv)) as JsonWebKey;
    const privateKey = await crypto.subtle.importKey('jwk', privateJwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']); const client = clientData('webauthn.get', options.challenge as string, origin);
    const nextCounter = passkey.signCounter + 1; const authData = await authenticatorData(rpId, 0x05, nextCounter); const signature = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, concat(authData, await hash(client))));
    return { nextCounter, responseJson: JSON.stringify({ id: passkey.credentialId, rawId: passkey.credentialId, type: 'public-key', response: { clientDataJSON: b64url(client), authenticatorData: b64url(authData), signature: b64url(signature), userHandle: passkey.userHandle }, clientExtensionResults: {} }) };
}
