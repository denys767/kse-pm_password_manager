/** Key-unwrap chains for vault items.
 *
 *  local-only:   KEK ──unwraps──▶ item key
 *  direct share: my RSA private key ──unwraps──▶ item key
 *  collection:   my RSA private key ──unwraps──▶ collection key ──unwraps──▶ item key
 */
import * as pmc from './crypto';
import type { VaultKeys } from './auth';
import type { Collection, PasswordItem } from './types';

export async function unwrapCollectionKey(
    collectionId: string, collections: Collection[], keys: VaultKeys): Promise<CryptoKey> {
    const collection = collections.find((c) => c.id === collectionId);
    if (!collection) {
        throw new Error('Ви не член колекції цього запису.');
    }
    // The collection key is an AES key wrapped RSA-OAEP, same as an item key.
    return pmc.unwrapItemKey(collection.myWrappedKey, keys.privateKey);
}

export async function unwrapItemKeyFor(
    item: PasswordItem, collections: Collection[], keys: VaultKeys): Promise<CryptoKey> {
    if (item.syncMode === 'LOCAL_ONLY') {
        return pmc.unwrapItemKeyWithKek(item.kekWrappedKey!.ct, item.kekWrappedKey!.iv, keys.kek);
    }
    if (item.wrappedKey) {
        return pmc.unwrapItemKey(item.wrappedKey, keys.privateKey);
    }
    if (item.collectionId && item.collectionWrappedKey) {
        const collectionKey = await unwrapCollectionKey(item.collectionId, collections, keys);
        return pmc.unwrapItemKeyWithKek(
            item.collectionWrappedKey, item.collectionWrappedKeyIv!, collectionKey);
    }
    throw new Error('Для вас ще не надано ключ до цього запису '
        + '(попросіть owner-а поділитися напряму або через колекцію).');
}
