import { ChangeEvent, FormEvent, useEffect, useRef, useState } from 'react';
import qrcode from 'qrcode-generator';
import jsQR from 'jsqr';
import { api, apiBinary, ApiError } from '../api';
import * as pmc from '../crypto';
import { unwrapCollectionKey, unwrapItemKeyFor } from '../itemKeys';
import { loadLocalItems, saveLocalItems } from '../localItems';
import { estimateStrength, generatePassword, hibpBreachCount } from '../passwords';
import { emptyPayload, parsePayload, serializePayload } from '../payload';
import { encryptShareSnapshot } from '../externalShare';
import { IconCheck, IconEye, IconEyeOff, IconRefresh, IconUser, IconUsers, IconWarning } from './Icons';
import { DirectoryPicker } from './DirectoryPicker';
import { parseTags, serializeTags } from '../tags';
import { useI18n } from '../i18n';
import type { Session } from '../App';
import type { AttachmentMetadata, Collection, DirectoryPrincipal, ItemVersion, PasswordItem, Permission, PermissionMemberInfo, SecretType, Settings } from '../types';

interface Props {
    session: Session;
    settings: Settings;
    collections: Collection[];
    /** null = add mode */
    item: PasswordItem | null;
    availableTags: string[];
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
    type: 'PERSONAL' | 'SHARED';
    sync: boolean;
}

export function ItemDialog({ session, settings, collections, item, availableTags, onClose }: Props) {
    const { t } = useI18n();
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
    const [shareForm, setShareForm] = useState({ grantee: '', role: 'VIEWER', principal: null as DirectoryPrincipal | null });
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
    const [tagDraft, setTagDraft] = useState('');
    const [attachmentFile, setAttachmentFile] = useState<File | null>(null);

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
                if (full.syncMode !== 'LOCAL_ONLY' && full.encryptedPassword) {
                    try {
                        full.attachment = await api<AttachmentMetadata>(`/api/vault/items/${full.id}/attachment`);
                    } catch (e) {
                        if ((e as ApiError).status !== 404) throw e;
                    }
                }
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

    const tagList = parseTags(fields.tags);
    function addTags(raw: string) {
        const next = parseTags([...tagList, ...raw.split(',')].join(','));
        set('tags', serializeTags(next) ?? ''); setTagDraft('');
    }
    function removeTag(tag: string) {
        set('tags', serializeTags(tagList.filter((candidate) => candidate.toLocaleLowerCase() !== tag.toLocaleLowerCase())) ?? '');
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
                sshPublicKey: fields.sshPublicKey,
                databaseType: fields.databaseType,
                databaseHost: fields.databaseHost,
                databasePort: fields.databasePort,
                databaseName: fields.databaseName,
                databaseUsername: fields.databaseUsername,
                databasePassword: fields.databasePassword,
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
                if (attachmentFile) {
                    await uploadAttachment(itemId, key, attachmentFile);
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

    /** The selected file is encrypted before it crosses the browser boundary.
     * There is intentionally no client-side size gate: Drive/Workspace quotas
     * and the Drive protocol are the only applicable limits. */
    async function uploadAttachment(itemId: string, key: CryptoKey, file: File) {
        const encrypted = await pmc.encryptAttachment(file, key);
        const encodedMetadata = btoa(JSON.stringify({
            encryptedFilename: encrypted.encryptedFilename.ct,
            encryptedFilenameIv: encrypted.encryptedFilename.iv,
            mimeType: file.type || 'application/octet-stream',
            ciphertextSize: encrypted.ciphertext.byteLength,
            ciphertextSha256: encrypted.ciphertextSha256,
            nonce: encrypted.nonce,
            wrappedFileKey: encrypted.wrappedFileKey.ct,
            wrappedFileKeyIv: encrypted.wrappedFileKey.iv,
        })).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
        try {
            const response = await apiBinary(`/api/vault/items/${itemId}/attachment`, {
                method: 'PUT', body: encrypted.ciphertext,
                headers: { 'Content-Type': 'application/octet-stream', 'X-Kse-Attachment-Metadata': encodedMetadata },
            });
            const metadata = await response.json() as AttachmentMetadata;
            setCurrent((value) => value ? { ...value, attachment: metadata } : value);
            setAttachmentFile(null);
        } catch (e) { throw e; }
    }

    async function downloadAttachment() {
        if (!current?.attachment || !itemKey) return;
        setError(null);
        try {
            const encrypted = await apiBinary(`/api/vault/items/${current.id}/attachment/content`);
            const attachment = current.attachment;
            const [filename, plaintext] = await Promise.all([
                pmc.decryptAttachmentFilename(
                    { ct: attachment.encryptedFilename, iv: attachment.encryptedFilenameIv },
                    { ct: attachment.wrappedFileKey, iv: attachment.wrappedFileKeyIv }, itemKey),
                encrypted.arrayBuffer().then((ciphertext) => pmc.decryptAttachment(ciphertext, attachment.nonce,
                    { ct: attachment.wrappedFileKey, iv: attachment.wrappedFileKeyIv }, itemKey)),
            ]);
            const link = document.createElement('a');
            link.href = URL.createObjectURL(new Blob([plaintext], { type: attachment.mimeType }));
            link.download = filename;
            link.click();
            URL.revokeObjectURL(link.href);
        } catch (e) { setError((e as Error).message); }
    }

    async function deleteAttachment() {
        if (!current?.attachment || !confirm('Видалити вкладення?')) return;
        try {
            await api(`/api/vault/items/${current.id}/attachment`, { method: 'DELETE' });
            setCurrent({ ...current, attachment: null });
        } catch (e) { setError((e as Error).message); }
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

    /** Reads a TOTP QR image entirely in the browser; the seed is never uploaded. */
    async function importTotpQr(event: ChangeEvent<HTMLInputElement>) {
        const file = event.target.files?.[0];
        event.target.value = '';
        if (!file) return;
        setError(null);
        try {
            const bitmap = await createImageBitmap(file);
            const canvas = document.createElement('canvas');
            canvas.width = bitmap.width; canvas.height = bitmap.height;
            const context = canvas.getContext('2d', { willReadFrequently: true });
            if (!context) throw new Error('Браузер не підтримує читання зображення.');
            context.drawImage(bitmap, 0, 0);
            bitmap.close();
            const image = context.getImageData(0, 0, canvas.width, canvas.height);
            const decoded = jsQR(image.data, image.width, image.height, { inversionAttempts: 'attemptBoth' });
            if (!decoded) throw new Error('QR-код не знайдено у вибраному файлі.');
            const uri = decoded.data.trim();
            const parsed = new URL(uri);
            if (parsed.protocol !== 'otpauth:' || parsed.hostname.toLowerCase() !== 'totp') {
                throw new Error('QR-код не містить TOTP otpauth URI.');
            }
            // Validate the actual Base32 secret before placing it in the encrypted form.
            pmc.decodeTotpSeed(uri);
            set('totpSeed', uri);
        } catch (e) {
            setError(`Не вдалося імпортувати TOTP QR: ${(e as Error).message}`);
        }
    }

    async function share() {
        const grantee = (shareForm.principal?.email ?? shareForm.grantee).trim().toLowerCase();
        if (!grantee || !current) {
            return;
        }
        setError(null);
        try {
            if (!itemKey) {
                throw new Error('Немає ключа запису — розшифруйте запис перед шерингом.');
            }
            if (shareForm.principal?.type === 'GROUP') {
                const created = await api<Permission>(`/api/vault/items/${current.id}/permissions`, {
                    method: 'POST', body: JSON.stringify({ granteeType: 'GROUP', grantee,
                        directorySubjectId: shareForm.principal.id, role: shareForm.role }),
                });
                setError(created.warning ?? 'Групу додано. Видайте ключі доступним учасникам кнопкою Provision.');
                setShareForm({ grantee: '', role: shareForm.role, principal: null });
                setPermissions(await api<Permission[]>(`/api/vault/items/${current.id}/permissions`));
                return;
            }
            let recipient: { publicKey: string };
            try {
                recipient = await api(`/api/keys/${encodeURIComponent(grantee)}`);
            } catch (e) {
                throw (e as ApiError).status === 404
                    ? new Error(t('noKeysForUser', { user: grantee }))
                    : e;
            }
            const recipientKey = await pmc.importPublicKey(recipient.publicKey);
            const body: Record<string, unknown> = {
                granteeType: 'USER',
                grantee,
                directorySubjectId: shareForm.principal?.id,
                role: shareForm.role,
                wrappedKey: await pmc.wrapItemKey(itemKey, recipientKey),
            };
            const created = await api<Permission>(`/api/vault/items/${current.id}/permissions`, {
                method: 'POST',
                body: JSON.stringify(body),
            });
            if (created.warning) {
                setError(created.warning);
            }
            setShareForm({ grantee: '', role: shareForm.role, principal: null });
            setCurrent({ ...current, itemType: 'SHARED' });
            set('type', 'SHARED');
            setPermissions(await api<Permission[]>(`/api/vault/items/${current.id}/permissions`));
        } catch (e) {
            setError((e as Error).message);
        }
    }


    async function provisionGroup(permission: Permission) {
        if (!current || !itemKey) return;
        try {
            const members = await api<PermissionMemberInfo[]>(`/api/vault/items/${current.id}/permissions/${permission.id}/members`);
            const pending = members.filter((member) => member.status === 'PENDING_PROVISIONING');
            const keys = await api<Record<string, { publicKey: string }>>('/api/keys/lookup', {
                method: 'POST', body: JSON.stringify(pending.map((member) => member.memberEmail)),
            });
            const provisioned = await Promise.all(pending.filter((member) => keys[member.memberEmail]).map(async (member) => ({
                email: member.memberEmail,
                wrappedKey: await pmc.wrapItemKey(itemKey, await pmc.importPublicKey(keys[member.memberEmail].publicKey)),
            })));
            if (provisioned.length === 0) { setError('У жодного pending учасника ще немає ключів у vault.'); return; }
            await api(`/api/vault/items/${current.id}/permissions/${permission.id}/provision`, {
                method: 'POST', body: JSON.stringify({ members: provisioned }),
            });
            setPermissions(await api<Permission[]>(`/api/vault/items/${current.id}/permissions`));
        } catch (e) { setError((e as Error).message); }
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
                    sshPrivateKey: fields.sshPrivateKey, sshPublicKey: fields.sshPublicKey,
                    databaseType: fields.databaseType, databaseHost: fields.databaseHost,
                    databasePort: fields.databasePort, databaseName: fields.databaseName,
                    databaseUsername: fields.databaseUsername, databasePassword: fields.databasePassword,
                    cardNumber: fields.cardNumber,
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

    async function extendExternalShare() {
        if (!current || !externalLink) return;
        try {
            const extended = await api<{ expiresAt: string; oneTime: boolean }>(
                `/api/vault/items/${current.id}/external-shares/${externalLink.id}/extend-24-hours`, { method: 'POST' });
            setError(`Посилання продовжено до ${new Date(extended.expiresAt).toLocaleString()}${extended.oneTime ? ' (одноразове)' : ''}. URL не змінено.`);
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
            sshPublicKey: fields.sshPublicKey,
            databaseType: fields.databaseType,
            databaseHost: fields.databaseHost,
            databasePort: fields.databasePort,
            databaseName: fields.databaseName,
            databaseUsername: fields.databaseUsername,
            databasePassword: fields.databasePassword,
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

    // Sharing only makes sense for a Shared record. Existing grants keep the
    // section visible so the owner can still revoke them — the server refuses
    // to turn a shared item back into a personal one until they are gone.
    const showShare = current !== null && isOwner && current.syncMode !== 'LOCAL_ONLY' && loaded
        && (sharedType || permissions.length > 0);

    return (
        <>
            <dialog id="item-dialog" ref={dialogRef} onClose={() => onClose(false)}>
                <form id="item-form" onSubmit={save}>
                    <h3 id="dialog-title">{current ? current.name : t('addPassword')}</h3>
                    <label>{t('name')}*
                        <input id="f-name" required maxLength={255} readOnly={!canEdit}
                               value={fields.name} onChange={(e) => set('name', e.target.value)} />
                    </label>
                    <label>URL
                        <input id="f-url" type="url" maxLength={2048} readOnly={!canEdit}
                               value={fields.url} onChange={(e) => set('url', e.target.value)} />
                    </label>
                    <label>{t('username')}
                        <input id="f-username" maxLength={255} autoComplete="off" readOnly={!canEdit}
                               value={fields.username} onChange={(e) => set('username', e.target.value)} />
                    </label>
                    {fields.secretType === 'LOGIN' && <label>{t('password')}*
                        <div className="row form-control-row">
                            <input id="f-password" type={showPassword ? 'text' : 'password'} required
                                   autoComplete="new-password" readOnly={!canEdit}
                                   value={fields.password}
                                   onChange={(e) => set('password', e.target.value)} />
                            <button type="button" id="toggle-pass" className="secondary small icon-btn"
                                    title={showPassword ? t('hidePassword') : t('showPassword')}
                                    aria-label={showPassword ? t('hidePassword') : t('showPassword')}
                                    onClick={() => setShowPassword((v) => !v)}>{showPassword ? <IconEyeOff /> : <IconEye />}</button>
                            {canEdit && (
                                <button type="button" id="generate-pass" className="secondary small icon-btn"
                                        title={t('generatePassword')} aria-label={t('generatePassword')} onClick={generate}><IconRefresh /></button>
                            )}
                            {current && itemKey && (
                                <button type="button" id="copy-pass" className="secondary small"
                                        onClick={copyPassword}>{copyLabel === 'Copy' ? t('copy') : copyLabel}</button>
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
                        <select id="f-secret-type" disabled={!canEdit || current !== null} value={fields.secretType}
                                onChange={(e) => set('secretType', e.target.value as SecretType)}>
                            <option value="LOGIN">Login</option>
                            <option value="API_CREDENTIALS">API credentials</option>
                            <option value="SSH_KEY">SSH key</option>
                            <option value="DATABASE">Database</option>
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
                    {fields.secretType === 'SSH_KEY' && <label>Public key
                        <textarea id="f-ssh-public-key" rows={4} autoComplete="off" readOnly={!canEdit}
                                  value={fields.sshPublicKey} onChange={(e) => set('sshPublicKey', e.target.value)} />
                    </label>}
                    {fields.secretType === 'DATABASE' && <>
                        <label>Database engine
                            <input id="f-database-type" placeholder="PostgreSQL" readOnly={!canEdit}
                                   value={fields.databaseType} onChange={(e) => set('databaseType', e.target.value)} />
                        </label>
                        <label>Host
                            <input id="f-database-host" autoComplete="off" readOnly={!canEdit}
                                   value={fields.databaseHost} onChange={(e) => set('databaseHost', e.target.value)} />
                        </label>
                        <div className="row">
                            <label>Port
                                <input id="f-database-port" inputMode="numeric" readOnly={!canEdit}
                                       value={fields.databasePort} onChange={(e) => set('databasePort', e.target.value)} />
                            </label>
                            <label>Database
                                <input id="f-database-name" autoComplete="off" readOnly={!canEdit}
                                       value={fields.databaseName} onChange={(e) => set('databaseName', e.target.value)} />
                            </label>
                        </div>
                        <label>Database user
                            <input id="f-database-username" autoComplete="off" readOnly={!canEdit}
                                   value={fields.databaseUsername} onChange={(e) => set('databaseUsername', e.target.value)} />
                        </label>
                        <label>Password
                            <input id="f-database-password" type="password" autoComplete="new-password" readOnly={!canEdit}
                                   value={fields.databasePassword} onChange={(e) => set('databasePassword', e.target.value)} />
                        </label>
                    </>}
                    {current && <p className="hint">Шаблон секрету фіксується під час створення запису.</p>}
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
                        {canEdit && <label>Імпортувати TOTP QR
                            <input id="import-totp-qr" type="file" accept="image/png,image/jpeg,image/webp,image/gif"
                                   onChange={importTotpQr} />
                            <span className="hint">Зображення обробляється лише у браузері.</span>
                        </label>}
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
                    <label>{t('notes')}
                        <textarea id="f-notes" rows={3} readOnly={!canEdit}
                                  value={fields.notes} onChange={(e) => set('notes', e.target.value)} />
                    </label>
                    <label>{t('tags')}
                        <div className="tag-editor" aria-label={t('tags')}>
                            {tagList.map((tag) => <span className="tag-chip" key={tag.toLocaleLowerCase()}>{tag}{canEdit && <button type="button" aria-label={`${t('delete')} ${tag}`} onClick={() => removeTag(tag)}>×</button>}</span>)}
                            {canEdit && <input id="f-tags" list="tag-suggestions" maxLength={1024} value={tagDraft} placeholder={t('tagsHelp')}
                                onChange={(e) => setTagDraft(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ',' || (e.key === ' ' && tagDraft.trim())) { e.preventDefault(); addTags(tagDraft); } else if (e.key === 'Backspace' && !tagDraft && tagList.length) removeTag(tagList[tagList.length - 1]); }} onBlur={() => tagDraft && addTags(tagDraft)} />}
                        </div>
                        <datalist id="tag-suggestions">{availableTags.filter((tag) => !tagList.some((selected) => selected.toLocaleLowerCase() === tag.toLocaleLowerCase())).map((tag) => <option key={tag} value={tag} />)}</datalist>
                    </label>
                    <label>{t('itemType')}
                        <select id="f-type" disabled={!isOwner} value={fields.type}
                                onChange={(e) => set('type', e.target.value as Fields['type'])}>
                            <option value="PERSONAL">Personal</option>
                            <option value="SHARED">Shared</option>
                        </select>
                    </label>
                    {isOwner && fields.sync && collections.length > 0 && (
                        <label>{t('collection')}
                            <select id="f-collection" value={collectionSel}
                                    onChange={(e) => setCollectionSel(e.target.value)}>
                                <option value="">{t('noCollection')}</option>
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
                    {fields.sync && canEdit && <section id="attachment-section">
                        <h4>Вкладення</h4>
                        <p className="hint">Одне вкладення шифрується AES-GCM у браузері та зберігається як непрозорий файл у Google Drive власника. Ліміт розміру не встановлюється застосунком; діють лише квоти й обмеження Google Drive.</p>
                        {current?.attachment && !attachmentFile && <div className="row attachment-row">
                            <span>Зашифроване вкладення · {current.attachment.ciphertextSize.toLocaleString()} B</span>
                            <button type="button" className="secondary small" onClick={downloadAttachment}>Завантажити</button>
                            {isOwner && <button type="button" className="secondary small" onClick={deleteAttachment}>{t('delete')}</button>}
                        </div>}
                        {isOwner && <label>Замінити вкладення
                            <input id="f-attachment" type="file" onChange={(event) => setAttachmentFile(event.target.files?.[0] ?? null)} />
                            {attachmentFile && <span className="hint">Буде зашифровано і завантажено після Save: {attachmentFile.name} ({attachmentFile.size.toLocaleString()} B)</span>}
                        </label>}
                        {!isOwner && <p className="hint">Вкладення недоступне для заміни без прав власника.</p>}
                    </section>}
                    {!fields.sync && <p className="hint">Local-only записи виключені з вкладень Drive і серверних адміністраторських операцій.</p>}

                    {showShare && (
                        <div id="share-section">
                            <h4>{t('sharedAccess')}</h4>
                            <ul id="permission-list" className="permission-list">
                                {permissions.map((p) => (
                                    <li key={p.id}>
                                        <span className="row">{p.granteeType === 'GROUP' ? <IconUsers /> : <IconUser />} {p.grantee} — {p.role.toLowerCase()}</span>
                                        <span className="row">
                                            {p.granteeType === 'GROUP' && p.status === 'ACTIVE' && <button type="button" className="secondary small" onClick={() => provisionGroup(p)}>Provision</button>}
                                            <button type="button" className="secondary small" onClick={() => revoke(p.id)}>{t('revoke')}</button>
                                        </span>
                                    </li>
                                ))}
                            </ul>
                            <div className="row share-controls">
                                <DirectoryPicker id="share-grantee" types="USER,GROUP"
                                        placeholder={t('directoryPickerPlaceholder')}
                                        value={shareForm.grantee}
                                        onTextChange={(text) => setShareForm((form) => ({ ...form, grantee: text, principal: null }))}
                                        onSelect={(principal) => setShareForm((form) => ({ ...form, grantee: principal.email, principal }))} />
                                <select id="share-role" value={shareForm.role}
                                        onChange={(e) => setShareForm({ ...shareForm, role: e.target.value })}>
                                    <option value="VIEWER">Viewer</option>
                                    <option value="EDITOR">Editor</option>
                                    <option value="AUTOFILL_ONLY">Autofill Only (extension)</option>
                                    <option value="PASSKEY_ONLY">Passkey Only</option>
                                </select>
                                <button type="button" id="share-btn" className="secondary" onClick={share}>{t('share')}</button>
                            </div>
                        </div>
                    )}
                    {showShare && <section id="external-share-section">
                        <h4>{t('externalShare')}</h4>
                        <p className="hint">Окремий зашифрований снапшот; AES-ключ є лише після <code>#</code> у посиланні.</p>
                        <div className="row external-share-controls">
                            <label>Строк дії<select id="external-share-ttl" value={externalTtl} onChange={(e) => setExternalTtl(e.target.value)}>
                                <option value="900">15 хвилин</option><option value="3600">1 година</option>
                                <option value="86400">24 години</option><option value="604800">7 днів</option>
                            </select></label>
                            <label className="checkbox-row"><input id="external-share-one-time" type="checkbox" checked={externalOneTime} onChange={(e) => setExternalOneTime(e.target.checked)} /> Одноразовий перегляд</label>
                            <button type="button" id="external-share-create" className="secondary" onClick={shareExternally}>{t('createLink')}</button>
                        </div>
                        {externalLink && <div className="external-link"><input readOnly value={externalLink.url} aria-label="External share link" />
                            <button type="button" className="secondary small" onClick={() => navigator.clipboard.writeText(externalLink.url)}>{t('copy')}</button>
                            <button type="button" className="secondary small" onClick={extendExternalShare}>+24 год</button>
                            <button type="button" className="secondary small" onClick={revokeExternalShare}>{t('revoke')}</button></div>}
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
                        {current && isOwner && <button type="button" id="delete-btn" className="danger" onClick={remove}>{t('delete')}</button>}
                        <button type="button" id="cancel-btn" className="secondary"
                                onClick={() => { dialogRef.current?.close(); }}>{t('cancel')}</button>
                        {canEdit && <button type="submit" id="save-btn">{t('save')}</button>}
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
