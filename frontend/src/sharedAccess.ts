import type { Collection, PasswordItem } from './types';

export interface SharedAccessInfo {
    ownerEmail: string;
    collectionName: string | null;
    isViewOnly: boolean;
}

/** Items whose ownerEmail differs from the viewer's are shared-with-me; the
 * comparison also naturally excludes local-only items, which are always
 * namespaced under the current user's own email. */
export function describeSharedAccess(
    item: PasswordItem, viewerEmail: string, collections: Collection[],
): SharedAccessInfo | null {
    if (!item.ownerEmail || item.ownerEmail === viewerEmail) return null;
    const collection = item.collectionId ? collections.find((c) => c.id === item.collectionId) : undefined;
    return {
        ownerEmail: item.ownerEmail,
        collectionName: collection?.name ?? null,
        isViewOnly: item.accessRole === 'VIEWER',
    };
}
