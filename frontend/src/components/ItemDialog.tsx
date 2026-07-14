import { FormEvent, useEffect, useRef, useState } from 'react';
import { api, ApiError } from '../api';
import * as pmc from '../crypto';
import { loadLocalItems, saveLocalItems } from '../localItems';
import { estimateStrength, generatePassword, hibpBreachCount } from '../passwords';
import type { Session } from '../App';
import type { ItemVersion, PasswordItem, Permission, Settings } from '../types';

interface Props {
    session: Session;
    settings: Settings;
    /** null = add mode */
    item: PasswordItem | null;
    onClose: (changed: boolean) => void;
}

interface Fields {
    name: string;
    url: string;
    username: string;
    password: string;
    notes: string;
    tags: string;
    type: 'PERSONAL' | 'SHARED';
    sync: boolean;
}

export function ItemDialog({ session, settings, item, onClose }: Props) {
    const dialogRef = useRef<HTMLDialogElement>(null);
    const warningRef = useRef<HTMLDialogElement>(null);
    const warningResolve = useRef<((ok: boolean) => void) | null>(null);

    const [current, setCurrent] = useState<PasswordItem | null>(item);
    const [fields, setFields] = useState<Fields>({
        name: '', url: '', username: '', password: '', notes: '', tags: '',
        type: 'PERSONAL',
        sync: settings.defaultSyncMode !== 'LOCAL_ONLY',
    });
    const [itemKey, setItemKey] = useState<CryptoKey | null>(null);
    const [permissions, setPermissions] = useState<Permission[]>([]);
    const [shareForm, setShareForm] = useState({ type: 'USER', grantee: '', role: 'VIEWER' });
    const [error, setError] = useState<string | null>(null);
    const [showPassword, setShowPassword] = useState(false);
    const [copyLabel, setCopyLabel] = useState('Copy');
    const [loaded, setLoaded] = useState(item === null);
    const [hibpStatus, setHibpStatus] = useState<string | null>(null);
    const [versions, setVersions] = useState<ItemVersion[] | null>(null);

    const isOwner = !current || !current.accessRole || current.accessRole === 'OWNER';
    const canEdit = !current || ((isOwner || current.accessRole === 'EDITOR') && itemKey !== null);
    const sharedType = fields.type === 'SHARED';

    useEffect(() => {
        dialogRef.current?.showModal();
    }, []);

    /** Unwrap the AES key of an item: RSA for server items, KEK for local-only. */
    async function unwrapKey(target: PasswordItem): Promise<CryptoKey> {
        if (target.syncMode === 'LOCAL_ONLY') {
            return pmc.unwrapItemKeyWithKek(target.kekWrappedKey!.ct, target.kekWrappedKey!.iv, session.keys.kek);
        }
        if (!target.wrappedKey) {
            throw new Error('Для вас ще не надано ключ до цього запису '
                + '(group-share без ключа — попросіть owner-а поділитися напряму).');
        }
        return pmc.unwrapItemKey(target.wrappedKey, session.keys.privateKey);
    }

    useEffect(() => {
        if (!item) {
            return;
        }
        (async () => {
            try {
                // Server GET also records the ITEM_VIEWED audit event.
                const full = item.syncMode === 'LOCAL_ONLY'
                    ? item
                    : await api<PasswordItem>(`/api/vault/items/${item.id}`);
                setCurrent(full);
                let key: CryptoKey | null = null;
                let password = '';
                let notes = '';
                try {
                    key = await unwrapKey(full);
                    password = await pmc.decryptField(key, full.encryptedPassword, full.passwordIv);
                    notes = full.encryptedNotes
                        ? await pmc.decryptField(key, full.encryptedNotes, full.notesIv!)
                        : '';
                } catch (e) {
                    setError((e as Error).message.startsWith('Для вас')
                        ? (e as Error).message
                        : 'Не вдалося розшифрувати запис (ключ не підходить).');
                }
                setItemKey(key);
                setFields({
                    name: full.name,
                    url: full.url || '',
                    username: full.username || '',
                    password,
                    notes,
                    tags: full.tags || '',
                    type: full.itemType,
                    sync: full.syncMode !== 'LOCAL_ONLY',
                });
                const owner = !full.accessRole || full.accessRole === 'OWNER';
                if (owner && full.syncMode !== 'LOCAL_ONLY') {
                    setPermissions(await api<Permission[]>(`/api/vault/items/${full.id}/permissions`));
                }
            } catch (e) {
                setError((e as Error).message);
            } finally {
                setLoaded(true);
            }
        })();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    function set<K extends keyof Fields>(key: K, value: Fields[K]) {
        setFields((f) => {
            const next = { ...f, [key]: value };
            if (key === 'type' && value === 'SHARED') {
                next.sync = true;
            }
            return next;
        });
    }

    function confirmLocalOnly(): Promise<boolean> {
        return new Promise((resolve) => {
            warningResolve.current = resolve;
            warningRef.current?.showModal();
        });
    }

    function answerWarning(ok: boolean) {
        warningRef.current?.close();
        warningResolve.current?.(ok);
        warningResolve.current = null;
    }

    async function save(event: FormEvent) {
        event.preventDefault();
        setError(null);
        const wasLocal = current?.syncMode === 'LOCAL_ONLY';
        if (!fields.sync && !wasLocal) {
            if (!(await confirmLocalOnly())) {
                return;
            }
        }
        try {
            // Existing item keeps its key (recipients keep access); new one gets a fresh key.
            const key = itemKey ?? await pmc.generateItemKey();
            const password = await pmc.encryptField(key, fields.password);
            const notes = fields.notes ? await pmc.encryptField(key, fields.notes) : null;
            const payload: Record<string, unknown> = {
                name: fields.name.trim(),
                url: fields.url.trim() || null,
                username: fields.username.trim() || null,
                encryptedPassword: password.ct,
                passwordIv: password.iv,
                encryptedNotes: notes ? notes.ct : null,
                notesIv: notes ? notes.iv : null,
                tags: fields.tags.trim() || null,
                itemType: fields.type,
                syncMode: 'SERVER_SYNCED',
            };
            if (fields.sync) {
                if (current && !wasLocal) {
                    await api(`/api/vault/items/${current.id}`, { method: 'PUT', body: JSON.stringify(payload) });
                } else {
                    payload.wrappedKey = await pmc.wrapItemKey(key, session.keys.publicKey);
                    await api('/api/vault/items', { method: 'POST', body: JSON.stringify(payload) });
                    if (current && wasLocal) {
                        removeLocal(current.id);
                    }
                }
            } else {
                await saveLocalOnly(payload, key, wasLocal);
            }
            dialogRef.current?.close();
            onClose(true);
        } catch (e) {
            setError((e as Error).message);
        }
    }

    function removeLocal(id: string) {
        const email = session.user.email;
        saveLocalItems(email, loadLocalItems(email).filter((i) => i.id !== id));
    }

    async function saveLocalOnly(payload: Record<string, unknown>, key: CryptoKey, wasLocal: boolean) {
        if (payload.itemType === 'SHARED') {
            throw new Error('Shared-запис не може бути local-only.');
        }
        if (current && !wasLocal) {
            // The server removes its copy (with an audit event); we keep it locally.
            await api(`/api/vault/items/${current.id}/sync-mode`, {
                method: 'PATCH',
                body: JSON.stringify({ syncMode: 'LOCAL_ONLY' }),
            });
        }
        const email = session.user.email;
        const id = current && wasLocal ? current.id : `local-${crypto.randomUUID()}`;
        const stored: PasswordItem = {
            ...(payload as unknown as PasswordItem),
            id,
            syncMode: 'LOCAL_ONLY',
            kekWrappedKey: await pmc.wrapItemKeyWithKek(key, session.keys.kek),
            ownerEmail: email,
            accessRole: 'OWNER',
            wrappedKey: null,
            updatedAt: new Date().toISOString(),
        };
        saveLocalItems(email, [...loadLocalItems(email).filter((i) => i.id !== id), stored]);
    }

    async function remove() {
        if (!current || !confirm(`Видалити «${current.name}»?`)) {
            return;
        }
        if (current.syncMode === 'LOCAL_ONLY') {
            removeLocal(current.id);
        } else {
            await api(`/api/vault/items/${current.id}`, { method: 'DELETE' });
        }
        dialogRef.current?.close();
        onClose(true);
    }

    async function copyPassword() {
        if (!fields.password) {
            return;
        }
        await navigator.clipboard.writeText(fields.password);
        if (current && current.syncMode !== 'LOCAL_ONLY') {
            api(`/api/vault/items/${current.id}/copy-event`, { method: 'POST' }).catch(() => {});
        }
        const seconds = settings.clipboardClearSeconds;
        const value = fields.password;
        setTimeout(async () => {
            try {
                if ((await navigator.clipboard.readText()) === value) {
                    await navigator.clipboard.writeText('');
                }
            } catch { /* clipboard read may be blocked; best effort */ }
        }, seconds * 1000);
        setCopyLabel(`Copied (${seconds}s)`);
        setTimeout(() => setCopyLabel('Copy'), 2000);
    }

    async function share() {
        const grantee = shareForm.grantee.trim().toLowerCase();
        if (!grantee || !current) {
            return;
        }
        setError(null);
        try {
            const body: Record<string, unknown> = {
                granteeType: shareForm.type,
                grantee,
                role: shareForm.role,
            };
            if (shareForm.type === 'USER') {
                if (!itemKey) {
                    throw new Error('Немає ключа запису — розшифруйте запис перед шерингом.');
                }
                let recipient: { publicKey: string };
                try {
                    recipient = await api(`/api/keys/${encodeURIComponent(grantee)}`);
                } catch (e) {
                    throw (e as ApiError).status === 404
                        ? new Error(`У ${grantee} ще немає ключів — користувач має увійти у vault хоча б раз.`)
                        : e;
                }
                const recipientKey = await pmc.importPublicKey(recipient.publicKey);
                body.wrappedKey = await pmc.wrapItemKey(itemKey, recipientKey);
            }
            const created = await api<Permission>(`/api/vault/items/${current.id}/permissions`, {
                method: 'POST',
                body: JSON.stringify(body),
            });
            if (created.warning) {
                setError(`⚠ ${created.warning}`);
            }
            setShareForm({ ...shareForm, grantee: '' });
            setCurrent({ ...current, itemType: 'SHARED' });
            set('type', 'SHARED');
            setPermissions(await api<Permission[]>(`/api/vault/items/${current.id}/permissions`));
        } catch (e) {
            setError((e as Error).message);
        }
    }

    async function revoke(permissionId: string) {
        if (!current) {
            return;
        }
        await api(`/api/vault/items/${current.id}/permissions/${permissionId}`, { method: 'DELETE' });
        setPermissions(await api<Permission[]>(`/api/vault/items/${current.id}/permissions`));
    }

    function generate() {
        set('password', generatePassword());
        setShowPassword(true);
        setHibpStatus(null);
    }

    async function checkBreach() {
        if (!fields.password) {
            return;
        }
        setHibpStatus('Перевіряю…');
        try {
            const count = await hibpBreachCount(fields.password);
            setHibpStatus(count === 0
                ? '✅ Не знайдено у відомих витоках.'
                : `⚠ Знайдено у витоках ${count.toLocaleString()} разів — змініть пароль!`);
        } catch (e) {
            setHibpStatus((e as Error).message);
        }
    }

    async function toggleHistory() {
        if (versions !== null) {
            setVersions(null);
            return;
        }
        if (!current) {
            return;
        }
        setVersions(await api<ItemVersion[]>(`/api/vault/items/${current.id}/versions`));
    }

    /** Decrypt a snapshot (same item key) into the form; the user then saves. */
    async function restoreVersion(version: ItemVersion) {
        if (!itemKey) {
            return;
        }
        try {
            const password = await pmc.decryptField(itemKey, version.encryptedPassword, version.passwordIv);
            const notes = version.encryptedNotes
                ? await pmc.decryptField(itemKey, version.encryptedNotes, version.notesIv!)
                : '';
            setFields((f) => ({
                ...f,
                name: version.name,
                url: version.url || '',
                username: version.username || '',
                password,
                notes,
            }));
            setVersions(null);
            setError('Версію підставлено у форму — натисніть Save, щоб відновити.');
        } catch {
            setError('Не вдалося розшифрувати цю версію.');
        }
    }

    const showShare = current !== null && isOwner && current.syncMode !== 'LOCAL_ONLY' && loaded;

    return (
        <>
            <dialog id="item-dialog" ref={dialogRef} onClose={() => onClose(false)}>
                <form id="item-form" onSubmit={save}>
                    <h3 id="dialog-title">{current ? current.name : 'Add password'}</h3>
                    <label>Назва*
                        <input id="f-name" required maxLength={255} readOnly={!canEdit}
                               value={fields.name} onChange={(e) => set('name', e.target.value)} />
                    </label>
                    <label>URL
                        <input id="f-url" type="url" maxLength={2048} readOnly={!canEdit}
                               value={fields.url} onChange={(e) => set('url', e.target.value)} />
                    </label>
                    <label>Username / login
                        <input id="f-username" maxLength={255} autoComplete="off" readOnly={!canEdit}
                               value={fields.username} onChange={(e) => set('username', e.target.value)} />
                    </label>
                    <label>Пароль*
                        <div className="row">
                            <input id="f-password" type={showPassword ? 'text' : 'password'} required
                                   autoComplete="new-password" readOnly={!canEdit}
                                   value={fields.password}
                                   onChange={(e) => { set('password', e.target.value); setHibpStatus(null); }} />
                            <button type="button" id="toggle-pass" className="secondary small"
                                    onClick={() => setShowPassword((v) => !v)}>👁</button>
                            {canEdit && (
                                <button type="button" id="generate-pass" className="secondary small"
                                        title="Згенерувати пароль" onClick={generate}>🎲</button>
                            )}
                            {current && itemKey && (
                                <button type="button" id="copy-pass" className="secondary small"
                                        onClick={copyPassword}>{copyLabel}</button>
                            )}
                        </div>
                    </label>
                    {fields.password && (() => {
                        const s = estimateStrength(fields.password);
                        return (
                            <div className="strength">
                                <div className="strength-track">
                                    <div className={`strength-bar s${s.score}`}
                                         style={{ width: `${(s.score + 1) * 20}%` }} />
                                </div>
                                <span className="hint">
                                    {s.label} (~{s.bits} біт){' '}
                                    <button type="button" id="hibp-btn" className="linklike"
                                            onClick={checkBreach}>перевірити витік</button>
                                </span>
                                {hibpStatus && <span className="hint" id="hibp-status"> {hibpStatus}</span>}
                            </div>
                        );
                    })()}
                    <label>Notes
                        <textarea id="f-notes" rows={3} readOnly={!canEdit}
                                  value={fields.notes} onChange={(e) => set('notes', e.target.value)} />
                    </label>
                    <label>Теги (через кому)
                        <input id="f-tags" maxLength={1024} readOnly={!canEdit}
                               value={fields.tags} onChange={(e) => set('tags', e.target.value)} />
                    </label>
                    <label>Тип запису
                        <select id="f-type" disabled={!isOwner} value={fields.type}
                                onChange={(e) => set('type', e.target.value as Fields['type'])}>
                            <option value="PERSONAL">Personal</option>
                            <option value="SHARED">Shared</option>
                        </select>
                    </label>
                    <label className="row checkbox-row">
                        <input id="f-sync" type="checkbox" checked={fields.sync}
                               disabled={sharedType || !isOwner}
                               onChange={(e) => set('sync', e.target.checked)} />
                        <span>Зберігати на сервері</span>
                    </label>
                    <p className="hint" id="sync-hint">
                        {sharedType
                            ? 'Shared-записи завжди зберігаються на сервері, інакше sharing не працює.'
                            : 'Вимкнено — запис залишиться тільки в цьому браузері (у зашифрованому вигляді).'}
                    </p>

                    {showShare && (
                        <div id="share-section">
                            <h4>Доступ (sharing)</h4>
                            <ul id="permission-list" className="permission-list">
                                {permissions.map((p) => (
                                    <li key={p.id}>
                                        <span>{p.granteeType === 'GROUP' ? '👥' : '👤'} {p.grantee} — {p.role.toLowerCase()}</span>
                                        <button type="button" className="secondary small"
                                                onClick={() => revoke(p.id)}>Revoke</button>
                                    </li>
                                ))}
                            </ul>
                            <div className="row">
                                <select id="share-type" value={shareForm.type}
                                        onChange={(e) => setShareForm({ ...shareForm, type: e.target.value })}>
                                    <option value="USER">Користувач</option>
                                    <option value="GROUP">Група</option>
                                </select>
                                <input id="share-grantee" placeholder="email або назва групи"
                                       value={shareForm.grantee}
                                       onChange={(e) => setShareForm({ ...shareForm, grantee: e.target.value })} />
                                <select id="share-role" value={shareForm.role}
                                        onChange={(e) => setShareForm({ ...shareForm, role: e.target.value })}>
                                    <option value="VIEWER">Viewer</option>
                                    <option value="EDITOR">Editor</option>
                                </select>
                                <button type="button" id="share-btn" className="secondary" onClick={share}>Share</button>
                            </div>
                        </div>
                    )}

                    {current && current.syncMode !== 'LOCAL_ONLY' && itemKey && (
                        <div id="history-section">
                            <button type="button" id="history-btn" className="linklike"
                                    onClick={() => toggleHistory().catch((e) => setError((e as Error).message))}>
                                {versions === null ? 'Показати історію версій' : 'Сховати історію'}
                            </button>
                            {versions !== null && (
                                <ul id="version-list" className="permission-list">
                                    {versions.length === 0 && <li><span className="hint">Попередніх версій немає.</span></li>}
                                    {versions.map((version) => (
                                        <li key={version.id}>
                                            <span>{new Date(version.replacedAt).toLocaleString()} · {version.name} · {version.replacedBy}</span>
                                            {canEdit && (
                                                <button type="button" className="secondary small"
                                                        onClick={() => restoreVersion(version)}>Відновити</button>
                                            )}
                                        </li>
                                    ))}
                                </ul>
                            )}
                        </div>
                    )}

                    {error && <p id="dialog-error" className="error">{error}</p>}
                    <div className="dialog-actions">
                        {current && isOwner && (
                            <button type="button" id="delete-btn" className="danger" onClick={remove}>Delete</button>
                        )}
                        <span className="spacer"></span>
                        <button type="button" id="cancel-btn" className="secondary"
                                onClick={() => { dialogRef.current?.close(); }}>Cancel</button>
                        {canEdit && <button type="submit" id="save-btn">Save</button>}
                    </div>
                </form>
            </dialog>

            <dialog id="warning-dialog" ref={warningRef}>
                <h3>Local-only запис</h3>
                <p>
                    Цей запис не буде доступний з іншого пристрою і <strong>не може бути відновлений
                    адміністратором</strong>. Він зберігається лише в цьому браузері (у зашифрованому вигляді).
                </p>
                <div className="dialog-actions">
                    <button id="warning-cancel" className="secondary" type="button"
                            onClick={() => answerWarning(false)}>Скасувати</button>
                    <button id="warning-confirm" className="danger" type="button"
                            onClick={() => answerWarning(true)}>Зрозуміло, вимкнути синхронізацію</button>
                </div>
            </dialog>
        </>
    );
}
