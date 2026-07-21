import { FormEvent, useEffect, useRef, useState } from 'react';
import qrcode from 'qrcode-generator';
import { api, ApiError } from '../api';
import * as pmc from '../crypto';
import { unwrapCollectionKey, unwrapItemKeyFor } from '../itemKeys';
import { loadLocalItems, saveLocalItems } from '../localItems';
import { estimateStrength, generatePassword, hibpBreachCount } from '../passwords';
import { emptyPayload, parsePayload, serializePayload } from '../payload';
import { encryptShareSnapshot } from '../externalShare';
import { IconCheck, IconEye, IconEyeOff, IconRefresh, IconUser, IconUsers, IconWarning } from './Icons';
import type { Session } from '../App';
import type { Collection, ItemVersion, PasswordItem, Permission, SecretType, Settings } from '../types';

interface Props {
    session: Session;
    settings: Settings;
    collections: Collection[];
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
    secretType: SecretType;
    apiKey: string;
    apiSecret: string;
    sshPrivateKey: string;
    cardNumber: string;
    cardCvv: string;
    cardHolder: string;
    cardExpiry: string;
    totpSeed: string;
    type: 'PERSONAL' | 'SHARED';
    sync: boolean;
}

export function ItemDialog({ session, settings, collections, item, onClose }: Props) {
    const dialogRef = useRef<HTMLDialogElement>(null);
    const warningRef = useRef<HTMLDialogElement>(null);
    const warningResolve = useRef<((ok: boolean) => void) | null>(null);

    const [current, setCurrent] = useState<PasswordItem | null>(item);
    const [fields, setFields] = useState<Fields>({
        name: '', url: '', username: '', password: '', tags: '', secretType: 'LOGIN',
        ...emptyPayload(),
        notes: '',
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
    const [hibpStatus, setHibpStatus] = useState<{ kind: 'checking' | 'clean' | 'breached' | 'error'; message: string } | null>(null);
    const [versions, setVersions] = useState<ItemVersion[] | null>(null);
    const [collectionSel, setCollectionSel] = useState<string>(item?.collectionId ?? '');
    const [totpCode, setTotpCode] = useState('');
    const [totpSeconds, setTotpSeconds] = useState(30);
    const [totpQr, setTotpQr] = useState<string | null>(null);
    const [externalTtl, setExternalTtl] = useState('3600');
    const [externalOneTime, setExternalOneTime] = useState(false);
    const [externalLink, setExternalLink] = useState<{ id: string; url: string } | null>(null);

    const isOwner = !current || !current.accessRole || current.accessRole === 'OWNER';
    const canEdit = !current || ((isOwner || current.accessRole === 'EDITOR') && itemKey !== null);
    const sharedType = fields.type === 'SHARED';

    useEffect(() => {
        dialogRef.current?.showModal();
    }, []);

    /** Unwrap the AES key of an item through whichever chain applies
     * (local KEK, direct RSA share, or collection key). */
    async function unwrapKey(target: PasswordItem): Promise<CryptoKey> {
        return unwrapItemKeyFor(target, collections, session.keys);
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
                let payload = emptyPayload();
                try {
                    key = await unwrapKey(full);
                    password = await pmc.decryptField(key, full.encryptedPassword, full.passwordIv);
                    payload = parsePayload(full.encryptedNotes
                        ? await pmc.decryptField(key, full.encryptedNotes, full.notesIv!)
                        : '');
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
                    ...payload,
                    notes: payload.notes,
                    tags: full.tags || '',
                    secretType: full.type ?? 'LOGIN',
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

    /** Debounced auto-check: HIBP k-anonymity lookup fires shortly after typing stops. */
    useEffect(() => {
        if (fields.secretType !== 'LOGIN' || !fields.password) {
            setHibpStatus(null);
            return;
        }
        let cancelled = false;
        setHibpStatus({ kind: 'checking', message: 'Перевіряю…' });
        const timer = window.setTimeout(() => {
            hibpBreachCount(fields.password).then((count) => {
                if (cancelled) return;
                setHibpStatus(count === 0
                    ? { kind: 'clean', message: 'Не знайдено у відомих витоках.' }
                    : { kind: 'breached', message: `Знайдено у витоках ${count.toLocaleString()} разів — змініть пароль!` });
            }).catch((e: Error) => { if (!cancelled) setHibpStatus({ kind: 'error', message: e.message }); });
        }, 600);
        return () => { cancelled = true; window.clearTimeout(timer); };
    }, [fields.secretType, fields.password]);

    useEffect(() => {
        setTotpQr(null);
        if (fields.secretType !== 'LOGIN' || !fields.totpSeed) {
            setTotpCode('');
            return;
        }
        let cancelled = false;
        const update = () => {
            const now = Date.now();
            setTotpSeconds(30 - Math.floor((now % 30_000) / 1000));
            pmc.generateTotp(fields.totpSeed, now)
                .then((code) => { if (!cancelled) setTotpCode(code); })
                .catch(() => { if (!cancelled) setTotpCode(''); });
        };
        update();
        const timer = window.setInterval(update, 1000);
        return () => {
            cancelled = true;
            window.clearInterval(timer);
        };
    }, [fields.secretType, fields.totpSeed]);

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
            const notes = await pmc.encryptField(key, serializePayload({
                version: 1,
                notes: fields.notes,
                apiKey: fields.apiKey,
                apiSecret: fields.apiSecret,
                sshPrivateKey: fields.sshPrivateKey,
                cardNumber: fields.cardNumber,
                cardCvv: fields.cardCvv,
                cardHolder: fields.cardHolder,
                cardExpiry: fields.cardExpiry,
                totpSeed: fields.totpSeed,
            }));
            const payload: Record<string, unknown> = {
                name: fields.name.trim(),
                url: fields.url.trim() || null,
                username: fields.username.trim() || null,
                encryptedPassword: password.ct,
                passwordIv: password.iv,
                encryptedNotes: notes.ct,
                notesIv: notes.iv,
                tags: fields.tags.trim() || null,
                type: fields.secretType,
                itemType: fields.type,
                syncMode: 'SERVER_SYNCED',
            };
            if (fields.sync) {
                let itemId: string;
                if (current && !wasLocal) {
                    await api(`/api/vault/items/${current.id}`, { method: 'PUT', body: JSON.stringify(payload) });
                    itemId = current.id;
                } else {
                    payload.wrappedKey = await pmc.wrapItemKey(key, session.keys.publicKey);
                    const created = await api<PasswordItem>('/api/vault/items', {
                        method: 'POST',
                        body: JSON.stringify(payload),
                    });
                    itemId = created.id;
                    if (current && wasLocal) {
                        removeLocal(current.id);
                    }
                }
                if (isOwner) {
                    await assignCollection(itemId, key);
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

    /** Sync the collection assignment with the select: wrap the item key with
     * the collection key (client-side) and tell the server. */
    async function assignCollection(itemId: string, key: CryptoKey) {
        const desired = collectionSel || null;
        if (desired === (current?.collectionId ?? null)) {
            return;
        }
        if (!desired) {
            await api(`/api/vault/items/${itemId}/collection`, {
                method: 'PUT',
                body: JSON.stringify({ collectionId: null }),
            });
            return;
        }
        const collectionKey = await unwrapCollectionKey(desired, collections, session.keys);
        const wrapped = await pmc.wrapItemKeyWithKek(key, collectionKey);
        await api(`/api/vault/items/${itemId}/collection`, {
            method: 'PUT',
            body: JSON.stringify({
                collectionId: desired,
                wrappedKey: wrapped.ct,
                wrappedKeyIv: wrapped.iv,
            }),
        });
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

    async function copyTotp() {
        if (!totpCode) {
            return;
        }
        await navigator.clipboard.writeText(totpCode);
    }

    /** Renders the same seed as an otpauth QR so a phone authenticator can scan and hold it too. */
    function toggleTotpQr() {
        if (totpQr) {
            setTotpQr(null);
            return;
        }
        const uri = pmc.buildOtpAuthUri(fields.totpSeed, fields.username || fields.name);
        const qr = qrcode(0, 'M');
        qr.addData(uri);
        qr.make();
        setTotpQr(qr.createDataURL(6, 8));
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
                setError(created.warning);
            }
            setShareForm({ ...shareForm, grantee: '' });
            setCurrent({ ...current, itemType: 'SHARED' });
            set('type', 'SHARED');
            setPermissions(await api<Permission[]>(`/api/vault/items/${current.id}/permissions`));
        } catch (e) {
            setError((e as Error).message);
        }
    }

    async function shareExternally() {
        if (!current || !itemKey) return;
        setError(null);
        try {
            const encrypted = await encryptShareSnapshot({
                version: 1, name: fields.name, url: fields.url, username: fields.username,
                tags: fields.tags, type: fields.secretType, password: fields.password,
                payload: {
                    version: 1, notes: fields.notes, apiKey: fields.apiKey, apiSecret: fields.apiSecret,
                    sshPrivateKey: fields.sshPrivateKey, cardNumber: fields.cardNumber,
                    cardCvv: fields.cardCvv, cardHolder: fields.cardHolder,
                    cardExpiry: fields.cardExpiry, totpSeed: fields.totpSeed,
                },
            });
            const created = await api<{ id: string }>(`/api/vault/items/${current.id}/external-shares`, {
                method: 'POST',
                body: JSON.stringify({
                    encryptedPackage: encrypted.encryptedPackage, packageIv: encrypted.packageIv,
                    expiresAt: new Date(Date.now() + Number(externalTtl) * 1000).toISOString(),
                    oneTime: externalOneTime,
                }),
            });
            setExternalLink({ id: created.id, url: `${window.location.origin}/share/${created.id}#${encrypted.fragmentKey}` });
        } catch (e) { setError((e as Error).message); }
    }

    async function revokeExternalShare() {
        if (!current || !externalLink) return;
        try {
            await api(`/api/vault/items/${current.id}/external-shares/${externalLink.id}`, { method: 'DELETE' });
            setExternalLink(null);
        } catch (e) { setError((e as Error).message); }
    }

    /**
     * Rotates the item's AES key so the recipient being revoked cannot decrypt
     * anything written after this point, even if they saved the old wrapped
     * key. Skipped when there's no one else to re-wrap for, or when the item
     * lives in a collection (its key is wrapped by the collection key instead
     * — see CollectionsTab.removeMember for that rotation).
     */
    async function rotateItemKeyExcluding(remaining: Permission[]) {
        if (!current || !itemKey) {
            return;
        }
        const newKey = await pmc.generateItemKey();
        const password = await pmc.encryptField(newKey, fields.password);
        const notes = await pmc.encryptField(newKey, serializePayload({
            version: 1,
            notes: fields.notes,
            apiKey: fields.apiKey,
            apiSecret: fields.apiSecret,
            sshPrivateKey: fields.sshPrivateKey,
            cardNumber: fields.cardNumber,
            cardCvv: fields.cardCvv,
            cardHolder: fields.cardHolder,
            cardExpiry: fields.cardExpiry,
            totpSeed: fields.totpSeed,
        }));
        const wrappedKeys = [
            { granteeEmail: session.user.email, wrappedKey: await pmc.wrapItemKey(newKey, session.keys.publicKey) },
        ];
        for (const permission of remaining) {
            const recipient = await api<{ publicKey: string }>(`/api/keys/${encodeURIComponent(permission.grantee)}`);
            const recipientKey = await pmc.importPublicKey(recipient.publicKey);
            wrappedKeys.push({
                granteeEmail: permission.grantee,
                wrappedKey: await pmc.wrapItemKey(newKey, recipientKey),
            });
        }
        await api(`/api/vault/items/${current.id}/rotate-key`, {
            method: 'POST',
            body: JSON.stringify({
                encryptedPassword: password.ct,
                passwordIv: password.iv,
                encryptedNotes: notes.ct,
                notesIv: notes.iv,
                wrappedKeys,
            }),
        });
        setItemKey(newKey);
    }

    async function revoke(permissionId: string) {
        if (!current) {
            return;
        }
        const target = permissions.find((p) => p.id === permissionId);
        const remainingUserShares = permissions.filter(
            (p) => p.id !== permissionId && p.granteeType === 'USER');
        if (target?.granteeType === 'USER' && !current.collectionId && remainingUserShares.length > 0) {
            try {
                await rotateItemKeyExcluding(remainingUserShares);
            } catch (e) {
                setError(`Не вдалося ротувати ключ, revoke скасовано: ${(e as Error).message}`);
                return;
            }
        }
        await api(`/api/vault/items/${current.id}/permissions/${permissionId}`, { method: 'DELETE' });
        setPermissions(await api<Permission[]>(`/api/vault/items/${current.id}/permissions`));
    }

    function generate() {
        set('password', generatePassword());
        setShowPassword(true);
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
            const payload = parsePayload(version.encryptedNotes
                ? await pmc.decryptField(itemKey, version.encryptedNotes, version.notesIv!)
                : '');
            setFields((f) => ({
                ...f,
                name: version.name,
                url: version.url || '',
                username: version.username || '',
                password,
                ...payload,
                notes: payload.notes,
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
                    {fields.secretType === 'LOGIN' && <label>Пароль*
                        <div className="row">
                            <input id="f-password" type={showPassword ? 'text' : 'password'} required
                                   autoComplete="new-password" readOnly={!canEdit}
                                   value={fields.password}
                                   onChange={(e) => set('password', e.target.value)} />
                            <button type="button" id="toggle-pass" className="secondary small icon-btn"
                                    title={showPassword ? 'Приховати пароль' : 'Показати пароль'}
                                    aria-label={showPassword ? 'Приховати пароль' : 'Показати пароль'}
                                    onClick={() => setShowPassword((v) => !v)}>{showPassword ? <IconEyeOff /> : <IconEye />}</button>
                            {canEdit && (
                                <button type="button" id="generate-pass" className="secondary small icon-btn"
                                        title="Згенерувати пароль" aria-label="Згенерувати пароль" onClick={generate}><IconRefresh /></button>
                            )}
                            {current && itemKey && (
                                <button type="button" id="copy-pass" className="secondary small"
                                        onClick={copyPassword}>{copyLabel}</button>
                            )}
                        </div>
                    </label>}
                    {fields.secretType === 'LOGIN' && fields.password && (() => {
                        const s = estimateStrength(fields.password);
                        return (
                            <div className="strength">
                                <div className="strength-track">
                                    <div className={`strength-bar s${s.score}`}
                                         style={{ width: `${(s.score + 1) * 20}%` }} />
                                </div>
                                <span className="hint">{s.label} (~{s.bits} біт)</span>
                                {hibpStatus && (
                                    <span className={`hint hibp-status hibp-${hibpStatus.kind}`} id="hibp-status">
                                        {hibpStatus.kind === 'clean' && <IconCheck />}
                                        {(hibpStatus.kind === 'breached' || hibpStatus.kind === 'error') && <IconWarning />}
                                        {hibpStatus.message}
                                    </span>
                                )}
                            </div>
                        );
                    })()}
                    <label>Шаблон секрету
                        <select id="f-secret-type" disabled={!canEdit} value={fields.secretType}
                                onChange={(e) => set('secretType', e.target.value as SecretType)}>
                            <option value="LOGIN">Login</option>
                            <option value="API_CREDENTIALS">API credentials</option>
                            <option value="SSH_KEY">SSH key</option>
                            <option value="CARD">Card</option>
                            <option value="SECURE_NOTE">Secure note</option>
                        </select>
                    </label>
                    {fields.secretType === 'API_CREDENTIALS' && <>
                        <label>API key
                            <input id="f-api-key" autoComplete="off" readOnly={!canEdit}
                                   value={fields.apiKey} onChange={(e) => set('apiKey', e.target.value)} />
                        </label>
                        <label>API secret
                            <input id="f-api-secret" type="password" autoComplete="new-password" readOnly={!canEdit}
                                   value={fields.apiSecret} onChange={(e) => set('apiSecret', e.target.value)} />
                        </label>
                    </>}
                    {fields.secretType === 'SSH_KEY' && <label>Private key
                        <textarea id="f-ssh-private-key" rows={7} autoComplete="off" readOnly={!canEdit}
                                  value={fields.sshPrivateKey} onChange={(e) => set('sshPrivateKey', e.target.value)} />
                    </label>}
                    {fields.secretType === 'CARD' && <>
                        <label>Номер картки
                            <input id="f-card-number" inputMode="numeric" autoComplete="off" readOnly={!canEdit}
                                   value={fields.cardNumber} onChange={(e) => set('cardNumber', e.target.value)} />
                        </label>
                        <label>Власник картки
                            <input id="f-card-holder" autoComplete="off" readOnly={!canEdit}
                                   value={fields.cardHolder} onChange={(e) => set('cardHolder', e.target.value)} />
                        </label>
                        <div className="row">
                            <label>Термін дії
                                <input id="f-card-expiry" placeholder="MM/YY" autoComplete="off" readOnly={!canEdit}
                                       value={fields.cardExpiry} onChange={(e) => set('cardExpiry', e.target.value)} />
                            </label>
                            <label>CVV
                                <input id="f-card-cvv" type="password" inputMode="numeric" autoComplete="off" readOnly={!canEdit}
                                       value={fields.cardCvv} onChange={(e) => set('cardCvv', e.target.value)} />
                            </label>
                        </div>
                    </>}
                    {fields.secretType === 'LOGIN' && <>
                        <label>TOTP seed (Base32 або otpauth URI)
                            <input id="f-totp-seed" type="password" autoComplete="off" readOnly={!canEdit}
                                   value={fields.totpSeed} onChange={(e) => set('totpSeed', e.target.value)} />
                        </label>
                        {fields.totpSeed && <div className="row" id="totp-code">
                            <strong>{totpCode || 'Невірний seed'}</strong>
                            <span className="hint">оновлення через {totpSeconds} с</span>
                            {totpCode && <button type="button" id="copy-totp" className="secondary small"
                                                 onClick={copyTotp}>Copy</button>}
                            {totpCode && <button type="button" id="show-totp-qr" className="secondary small"
                                                 onClick={toggleTotpQr}>{totpQr ? 'Приховати QR' : 'Показати QR'}</button>}
                        </div>}
                        {totpQr && <div className="totp-qr">
                            <img src={totpQr} alt="TOTP QR code" width={160} height={160} />
                            <span className="hint">Відскануйте в Google Authenticator / Authy, щоб мати той самий код на телефоні.</span>
                        </div>}
                    </>}
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
                    {isOwner && fields.sync && collections.length > 0 && (
                        <label>Колекція
                            <select id="f-collection" value={collectionSel}
                                    onChange={(e) => setCollectionSel(e.target.value)}>
                                <option value="">— без колекції —</option>
                                {collections.map((collection) => (
                                    <option key={collection.id} value={collection.id}
                                            disabled={collection.myRole === 'VIEWER'}>
                                        {collection.name}
                                    </option>
                                ))}
                            </select>
                        </label>
                    )}
                    <label className="row checkbox-row">
                        <input id="f-sync" type="checkbox" checked={fields.sync}
                               disabled={sharedType || !isOwner || collectionSel !== ''}
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
                                        <span className="row">{p.granteeType === 'GROUP' ? <IconUsers /> : <IconUser />} {p.grantee} — {p.role.toLowerCase()}</span>
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
                    {showShare && <section id="external-share-section">
                        <h4>Share externally</h4>
                        <p className="hint">Окремий зашифрований снапшот; AES-ключ є лише після <code>#</code> у посиланні.</p>
                        <div className="row">
                            <label>Строк дії<select id="external-share-ttl" value={externalTtl} onChange={(e) => setExternalTtl(e.target.value)}>
                                <option value="900">15 хвилин</option><option value="3600">1 година</option>
                                <option value="86400">24 години</option><option value="604800">7 днів</option>
                            </select></label>
                            <label className="checkbox-row"><input id="external-share-one-time" type="checkbox" checked={externalOneTime} onChange={(e) => setExternalOneTime(e.target.checked)} /> Одноразовий перегляд</label>
                            <button type="button" id="external-share-create" className="secondary" onClick={shareExternally}>Create link</button>
                        </div>
                        {externalLink && <div className="external-link"><input readOnly value={externalLink.url} aria-label="External share link" />
                            <button type="button" className="secondary small" onClick={() => navigator.clipboard.writeText(externalLink.url)}>Copy</button>
                            <button type="button" className="secondary small" onClick={revokeExternalShare}>Revoke</button></div>}
                    </section>}

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
