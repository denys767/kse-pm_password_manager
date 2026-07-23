import { useEffect, useState } from 'react';
import { api, ApiError } from '../api';
import * as pmc from '../crypto';
import { unwrapCollectionKey } from '../itemKeys';
import { IconTrash, IconUser } from './Icons';
import { DirectoryPicker } from './DirectoryPicker';
import { useI18n } from '../i18n';
import type { Session } from '../App';
import type { Collection, CollectionMemberInfo, CollectionRole, PasswordItem } from '../types';

interface Props {
    session: Session;
    collections: Collection[];
    onChanged: () => Promise<void>;
}

export function CollectionsTab({ session, collections, onChanged }: Props) {
    const { t, language } = useI18n();
    const tr = (uk: string, en: string) => (language === 'uk' ? uk : en);
    const [name, setName] = useState('');
    const [directoryGroup, setDirectoryGroup] = useState('');
    const [availableGroups, setAvailableGroups] = useState<string[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [expanded, setExpanded] = useState<string | null>(null);
    const [members, setMembers] = useState<CollectionMemberInfo[]>([]);
    const [memberForm, setMemberForm] = useState({ email: '', role: 'VIEWER' as CollectionRole });
    const [avatars, setAvatars] = useState<Record<string, string | null>>({});

    useEffect(() => {
        api<string[]>('/api/collection-groups').then(setAvailableGroups).catch((e) => setError(e.message));
    }, []);

    useEffect(() => {
        const missing = members.map((m) => m.memberEmail.toLowerCase()).filter((email) => !(email in avatars));
        if (missing.length === 0) return;
        Promise.all(missing.map((email) => api<{ avatarDataUrl: string | null }>(`/api/settings/${encodeURIComponent(email)}/avatar`)
            .then((r) => [email, r.avatarDataUrl] as const)
            .catch(() => [email, null] as const)))
            .then((pairs) => setAvatars((prev) => ({ ...prev, ...Object.fromEntries(pairs) })));
    }, [members, avatars]);

    async function create() {
        if (!name.trim()) {
            return;
        }
        setError(null);
        try {
            // The collection key is a fresh AES key, wrapped for ourselves with RSA.
            const collectionKey = await pmc.generateItemKey();
            const wrappedKeyForSelf = await pmc.wrapItemKey(collectionKey, session.keys.publicKey);
            await api('/api/collections', {
                method: 'POST',
                    body: JSON.stringify({ name: name.trim(), directoryGroup: directoryGroup.trim() || null, wrappedKeyForSelf }),
            });
            setName('');
            setDirectoryGroup('');
            await onChanged();
        } catch (e) {
            setError((e as Error).message);
        }
    }

    async function toggleMembers(collection: Collection) {
        if (expanded === collection.id) {
            setExpanded(null);
            return;
        }
        setError(null);
        setMembers(await api<CollectionMemberInfo[]>(`/api/collections/${collection.id}/members`));
        setExpanded(collection.id);
    }

    async function provisionMember(collection: Collection, rawEmail: string, role: CollectionRole) {
        const email = rawEmail.trim().toLowerCase();
        if (!email) {
            return;
        }
        let recipient: { publicKey: string };
        try {
            recipient = await api(`/api/keys/${encodeURIComponent(email)}`);
        } catch (e) {
            throw (e as ApiError).status === 404
                ? new Error(t('noKeysForUser', { user: email }))
                : e;
        }
        // A suggestion never grants access: manager's browser explicitly wraps
        // the collection key with every selected recipient's public key.
        const collectionKey = await unwrapCollectionKey(collection.id, collections, session.keys);
        const recipientKey = await pmc.importPublicKey(recipient.publicKey);
        const wrappedKey = await pmc.wrapItemKey(collectionKey, recipientKey);
        await api(`/api/collections/${collection.id}/members`, {
            method: 'POST',
            body: JSON.stringify({ email, role, wrappedKey }),
        });
    }

    async function addMember(collection: Collection) {
        setError(null);
        try {
            await provisionMember(collection, memberForm.email, memberForm.role);
            setMemberForm({ ...memberForm, email: '' });
            setMembers(await api<CollectionMemberInfo[]>(`/api/collections/${collection.id}/members`));
            await onChanged();
        } catch (e) {
            setError((e as Error).message);
        }
    }

    async function syncGroup(collection: Collection) {
        if (!collection.directoryGroup) return;
        setError(null);
        try {
            await api(`/api/collections/${collection.id}/sync-group`, { method: 'POST' });
            setMembers(await api<CollectionMemberInfo[]>(`/api/collections/${collection.id}/members`));
            await onChanged();
        } catch (e) {
            setError((e as Error).message);
        }
    }

    /**
     * Rotates the collection key so the member being removed cannot decrypt
     * anything from now on, even if they saved the old key: a fresh collection
     * key is re-wrapped for every remaining member, and every collection
     * item's (unchanged) item key is re-wrapped with the new collection key.
     */
    async function rotateCollectionKeyExcluding(collection: Collection, removedMemberId: string) {
        const remainingMembers = members.filter((m) => m.id !== removedMemberId && m.status === 'ACTIVE');
        const oldCollectionKey = await unwrapCollectionKey(collection.id, collections, session.keys);
        const newCollectionKey = await pmc.generateItemKey();

        const memberWrappedKeys = [];
        for (const member of remainingMembers) {
            const recipient = await api<{ publicKey: string }>(
                `/api/keys/${encodeURIComponent(member.memberEmail)}`);
            const recipientKey = await pmc.importPublicKey(recipient.publicKey);
            memberWrappedKeys.push({
                memberId: member.id,
                wrappedKey: await pmc.wrapItemKey(newCollectionKey, recipientKey),
            });
        }

        const allItems = await api<PasswordItem[]>('/api/vault/items');
        const collectionItems = allItems.filter((item) => item.collectionId === collection.id);
        const itemWrappedKeys = [];
        for (const item of collectionItems) {
            const itemKey = await pmc.unwrapItemKeyWithKek(
                item.collectionWrappedKey!, item.collectionWrappedKeyIv!, oldCollectionKey);
            const wrapped = await pmc.wrapItemKeyWithKek(itemKey, newCollectionKey);
            itemWrappedKeys.push({ itemId: item.id, wrappedKey: wrapped.ct, wrappedKeyIv: wrapped.iv });
        }

        await api(`/api/collections/${collection.id}/rotate-key`, {
            method: 'POST',
            body: JSON.stringify({ memberWrappedKeys, itemWrappedKeys }),
        });
    }

    async function removeMember(collection: Collection, member: CollectionMemberInfo) {
        setError(null);
        try {
            if (members.filter((candidate) => candidate.status === 'ACTIVE').length > 1) {
                await rotateCollectionKeyExcluding(collection, member.id);
            }
            await api(`/api/collections/${collection.id}/members/${member.id}`, { method: 'DELETE' });
            setMembers(await api<CollectionMemberInfo[]>(`/api/collections/${collection.id}/members`));
            await onChanged();
        } catch (e) {
            setError(`Revoke: ${(e as Error).message}`);
        }
    }

    async function removeCollection(collection: Collection) {
        if (!confirm(tr(`Видалити колекцію «${collection.name}»?`, `Delete the collection “${collection.name}”?`))) {
            return;
        }
        setError(null);
        try {
            await api(`/api/collections/${collection.id}`, { method: 'DELETE' });
            setExpanded(null);
            await onChanged();
        } catch (e) {
            setError((e as Error).message);
        }
    }

    return (
        <section id="tab-collections" className="tab-panel">
            <div className="toolbar">
                <input id="collection-name" placeholder={t('collectionName')}
                       value={name} onChange={(e) => setName(e.target.value)} />
                <select id="directory-group" value={directoryGroup} onChange={(e) => setDirectoryGroup(e.target.value)}>
                    <option value="">{tr('Без доменної групи', 'No domain group')}</option>
                    {availableGroups.map((group) => <option key={group} value={group}>{group}</option>)}
                </select>
                <button id="create-collection-btn" onClick={create}>{t('createCollection')}</button>
            </div>
            <p className="hint">
                {tr('Колекція — командний vault: її ключ видається кожному члену окремо (обгорнутий його публічним ключем), тому всі члени можуть розшифровувати записи колекції.',
                    'A collection is a team vault: its key is granted to each member individually (wrapped with their public key), so every member can decrypt the collection’s items.')}
            </p>
            {error && <p className="error" id="collections-error">{error}</p>}
            <ul id="collection-list" className="item-list">
                {collections.map((collection) => (
                    <li key={collection.id} className="collection-item">
                        <div style={{ width: '100%' }}>
                            <div className="row collection-summary" role="button" tabIndex={0} aria-expanded={expanded === collection.id}
                                 onClick={() => toggleMembers(collection).catch((e) => setError(e.message))}
                                 onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); void toggleMembers(collection).catch((e) => setError(e.message)); } }}>
                                <div>
                                    <strong>{collection.name}</strong>
                                    <span className="badge">{collection.myRole.toLowerCase()}</span>
                                    <span className="item-meta"> {collection.memberCount} {t('members')} · {t('owner')} {collection.ownerEmail}</span>
                                    {collection.pendingProvisioningCount > 0 && <span className="item-meta"> · {collection.pendingProvisioningCount} pending provisioning</span>}
                                    {collection.pendingRemovalCount > 0 && <span className="item-meta"> · {collection.pendingRemovalCount} pending removal</span>}
                                </div>
                                <div className="row">
                                    {collection.ownerEmail === session.user.email && (
                                        <button type="button" className="danger small icon-btn" title={t('deleteCollection')} aria-label={t('deleteCollection')}
                                                onClick={(event) => { event.stopPropagation(); void removeCollection(collection); }}><IconTrash /></button>
                                    )}
                                </div>
                            </div>
                            {expanded === collection.id && (
                                <div style={{ marginTop: 8 }}>
                                    <ul className="permission-list" id="member-list">
                                        {members.map((member) => (
                                            <li key={member.id}>
                                                <span className="row">
                                                    {avatars[member.memberEmail.toLowerCase()]
                                                        ? <img className="avatar" src={avatars[member.memberEmail.toLowerCase()]!} alt="" width={20} height={20} />
                                                        : <IconUser />}
                                                    {' '}{member.memberEmail} — {member.role.toLowerCase()} {member.status !== 'ACTIVE' && `(${member.status.toLowerCase().replace('_', ' ')})`}
                                                </span>
                                                {collection.myRole === 'MANAGER'
                                                    && member.memberEmail !== collection.ownerEmail && (
                                                    <button type="button" className="secondary small"
                                                            onClick={() => member.status === 'PENDING_PROVISIONING'
                                                                ? provisionMember(collection, member.memberEmail, member.role)
                                                                    .then(async () => { setMembers(await api<CollectionMemberInfo[]>(`/api/collections/${collection.id}/members`)); await onChanged(); })
                                                                    .catch((e) => setError(e.message))
                                                                : removeMember(collection, member)}>
                                                        {member.status === 'PENDING_PROVISIONING' ? 'Provision key' : 'Revoke'}
                                                    </button>
                                                )}
                                            </li>
                                        ))}
                                    </ul>
                                    {collection.myRole === 'MANAGER' && (<>
                                        <div className="row">
                                            <DirectoryPicker id="member-email" types="USER"
                                                   placeholder={t('directoryUserPlaceholder')}
                                                   value={memberForm.email}
                                                   onTextChange={(text) => setMemberForm((form) => ({ ...form, email: text }))}
                                                   onSelect={(principal) => setMemberForm((form) => ({ ...form, email: principal.email }))} />
                                            <select id="member-role" value={memberForm.role}
                                                    onChange={(e) => setMemberForm({ ...memberForm, role: e.target.value as CollectionRole })}>
                                                <option value="VIEWER">Viewer</option>
                                                <option value="EDITOR">Editor</option>
                                                <option value="MANAGER">Manager</option>
                                            </select>
                                            <button type="button" id="add-member-btn" className="secondary"
                                                    onClick={() => addMember(collection)}>Add</button>
                                            {collection.directoryGroup && <button type="button" id="sync-group-btn" className="secondary"
                                                    onClick={() => syncGroup(collection)}>Sync group</button>}
                                        </div>
                                        {collection.pendingProvisioningCount > 0 && <p className="hint" id="pending-provisioning-banner">New group members have no access until you click “Provision key”.</p>}
                                        {collection.pendingRemovalCount > 0 && <p className="hint" id="pending-removal-banner">Removed group members are blocked; click “Revoke” to rotate the collection key and finalize removal.</p>}
                                    </>)}
                                </div>
                            )}
                        </div>
                    </li>
                ))}
            </ul>
            {collections.length === 0 && <p className="hint">{tr('Колекцій поки немає.', 'No collections yet.')}</p>}
        </section>
    );
}
