import { useState } from 'react';
import { api, ApiError } from '../api';
import * as pmc from '../crypto';
import { unwrapCollectionKey } from '../itemKeys';
import type { Session } from '../App';
import type { Collection, CollectionMemberInfo, CollectionRole } from '../types';

interface Props {
    session: Session;
    collections: Collection[];
    onChanged: () => Promise<void>;
}

export function CollectionsTab({ session, collections, onChanged }: Props) {
    const [name, setName] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [expanded, setExpanded] = useState<string | null>(null);
    const [members, setMembers] = useState<CollectionMemberInfo[]>([]);
    const [memberForm, setMemberForm] = useState({ email: '', role: 'VIEWER' as CollectionRole });

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
                body: JSON.stringify({ name: name.trim(), wrappedKeyForSelf }),
            });
            setName('');
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

    async function addMember(collection: Collection) {
        const email = memberForm.email.trim().toLowerCase();
        if (!email) {
            return;
        }
        setError(null);
        try {
            let recipient: { publicKey: string };
            try {
                recipient = await api(`/api/keys/${encodeURIComponent(email)}`);
            } catch (e) {
                throw (e as ApiError).status === 404
                    ? new Error(`У ${email} ще немає ключів — користувач має увійти у vault хоча б раз.`)
                    : e;
            }
            const collectionKey = await unwrapCollectionKey(collection.id, collections, session.keys);
            const recipientKey = await pmc.importPublicKey(recipient.publicKey);
            const wrappedKey = await pmc.wrapItemKey(collectionKey, recipientKey);
            await api(`/api/collections/${collection.id}/members`, {
                method: 'POST',
                body: JSON.stringify({ email, role: memberForm.role, wrappedKey }),
            });
            setMemberForm({ ...memberForm, email: '' });
            setMembers(await api<CollectionMemberInfo[]>(`/api/collections/${collection.id}/members`));
            await onChanged();
        } catch (e) {
            setError((e as Error).message);
        }
    }

    async function removeMember(collection: Collection, member: CollectionMemberInfo) {
        setError(null);
        try {
            await api(`/api/collections/${collection.id}/members/${member.id}`, { method: 'DELETE' });
            setMembers(await api<CollectionMemberInfo[]>(`/api/collections/${collection.id}/members`));
            await onChanged();
        } catch (e) {
            setError((e as Error).message);
        }
    }

    async function removeCollection(collection: Collection) {
        if (!confirm(`Видалити колекцію «${collection.name}»?`)) {
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
                <input id="collection-name" placeholder="Назва нової колекції (напр. Infra)"
                       value={name} onChange={(e) => setName(e.target.value)} />
                <button id="create-collection-btn" onClick={create}>+ Create collection</button>
            </div>
            <p className="hint">
                Колекція — командний vault: її ключ видається кожному члену окремо (обгорнутий його
                публічним ключем), тому всі члени можуть розшифровувати записи колекції.
            </p>
            {error && <p className="error" id="collections-error">{error}</p>}
            <ul id="collection-list" className="item-list">
                {collections.map((collection) => (
                    <li key={collection.id} className="collection-item">
                        <div style={{ width: '100%' }}>
                            <div className="row" style={{ justifyContent: 'space-between' }}>
                                <div>
                                    <strong>{collection.name}</strong>
                                    <span className="badge">{collection.myRole.toLowerCase()}</span>
                                    <span className="item-meta"> {collection.memberCount} member(s) · owner {collection.ownerEmail}</span>
                                </div>
                                <div className="row">
                                    <button type="button" className="secondary small"
                                            onClick={() => toggleMembers(collection).catch((e) => setError(e.message))}>
                                        {expanded === collection.id ? 'Hide members' : 'Members'}
                                    </button>
                                    {collection.ownerEmail === session.user.email && (
                                        <button type="button" className="danger small"
                                                onClick={() => removeCollection(collection)}>Delete</button>
                                    )}
                                </div>
                            </div>
                            {expanded === collection.id && (
                                <div style={{ marginTop: 8 }}>
                                    <ul className="permission-list" id="member-list">
                                        {members.map((member) => (
                                            <li key={member.id}>
                                                <span>👤 {member.memberEmail} — {member.role.toLowerCase()}</span>
                                                {collection.myRole === 'MANAGER'
                                                    && member.memberEmail !== collection.ownerEmail && (
                                                    <button type="button" className="secondary small"
                                                            onClick={() => removeMember(collection, member)}>Revoke</button>
                                                )}
                                            </li>
                                        ))}
                                    </ul>
                                    {collection.myRole === 'MANAGER' && (
                                        <div className="row">
                                            <input id="member-email" placeholder="email колеги"
                                                   value={memberForm.email}
                                                   onChange={(e) => setMemberForm({ ...memberForm, email: e.target.value })} />
                                            <select id="member-role" value={memberForm.role}
                                                    onChange={(e) => setMemberForm({ ...memberForm, role: e.target.value as CollectionRole })}>
                                                <option value="VIEWER">Viewer</option>
                                                <option value="EDITOR">Editor</option>
                                                <option value="MANAGER">Manager</option>
                                            </select>
                                            <button type="button" id="add-member-btn" className="secondary"
                                                    onClick={() => addMember(collection)}>Add</button>
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    </li>
                ))}
            </ul>
            {collections.length === 0 && <p className="hint">Колекцій поки немає.</p>}
        </section>
    );
}
