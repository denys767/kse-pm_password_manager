import { assertionResponse, createMaterial, createResponse } from './webauthn';

const item = { id: '00000000-0000-0000-0000-000000000001', name: 'Example', url: 'https://login.example.test', username: 'alice', encryptedPassword: '', passwordIv: '', encryptedNotes: null, notesIv: null, tags: null, type: 'LOGIN', itemType: 'PERSONAL', syncMode: 'SERVER_SYNCED', wrappedKey: null, collectionId: null, collectionWrappedKey: null, collectionWrappedKeyIv: null } as const;
void (async () => {
    const vault = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']) as CryptoKeyPair;
    const creation = await createResponse({ origin: 'https://login.example.test', challenge: 'AA', rp: { id: 'example.test' }, user: { id: 'AQ' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }] }, item, vault.publicKey);
    const publicResult = JSON.parse(creation.responseJson);
    if (publicResult.response.attestationObject === undefined || creation.payload.relyingPartyId !== 'example.test') throw new Error('ES256 none-attestation fixture failed');
    const assertion = await assertionResponse({ origin: 'https://login.example.test', challenge: 'AQ', rpId: 'example.test', allowCredentials: [{ type: 'public-key', id: creation.payload.credentialId }] }, { id: 'credential-row', itemId: item.id, relyingPartyId: 'example.test', credentialId: creation.payload.credentialId, userHandle: 'AQ', algorithm: 'ES256', publicKey: creation.payload.publicKey, encryptedPrivateMaterial: creation.payload.encryptedPrivateMaterial, privateMaterialIv: creation.payload.privateMaterialIv, transports: 'internal', signCounter: 7, wrappedCredentialKey: creation.payload.wrappedCredentialKey }, vault.privateKey);
    if (assertion.nextCounter !== 8 || !JSON.parse(assertion.responseJson).response.signature) throw new Error('assertion/counter fixture failed');
    let rejected = false;
    try { await createResponse({ origin: 'https://attacker.test', challenge: 'AA', rp: { id: 'example.test' }, user: { id: 'AQ' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }] }, item, vault.publicKey); } catch { rejected = true; }
    if (!rejected) throw new Error('origin validation fixture failed');
    console.log('webauthn fixtures: create, assertion counter, and origin validation passed');
})();
