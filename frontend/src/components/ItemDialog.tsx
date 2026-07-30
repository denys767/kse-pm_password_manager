import { ChangeEvent, FormEvent, useEffect, useRef, useState } from 'react';
import qrcode from 'qrcode-generator';
import jsQR from 'jsqr';
import { api, apiBinary, ApiError } from '../api';
import * as pmc from '../crypto';
import { unwrapCollectionKey, unwrapItemKeyFor } from '../itemKeys';
import { loadLocalItems, saveLocalItems } from '../localItems';
import { estimateStrength, generatePassword, hibpBreachCount } from '../passwords';
import { emptyPayload, parsePayload, serializePayload } from '../payload';
import { encryptShareSnapshot, MAX_ENCRYPTED_PACKAGE_CHARS } from '../externalShare';
import { IconCheck, IconEye, IconEyeOff, IconLock, IconPencil, IconRefresh, IconUser, IconUsers, IconWarning } from './Icons';
import { describeSharedAccess } from '../sharedAccess';
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

/** Accepts a bare host ("url.com") as well as a full URL: anything without an
 * explicit scheme gets an https:// prefix so stored links are always openable. */
function normalizeUrl(raw: string): string | null {
    const value = raw.trim();
    if (!value) return null;
    return /^[a-z][a-z0-9+.-]*:/i.test(value) ? value : `https://${value}`;
}

export function ItemDialog({ session, settings, collections, item, availableTags, onClose }: Props) {
    const { t, language } = useI18n();
    const tr = (uk: string, en: string) => (language === 'uk' ? uk : en);
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
    const [linkCopied, setLinkCopied] = useState(false);
    const [shareAvatars, setShareAvatars] = useState<Record<string, string | null>>({});
    const [tagDraft, setTagDraft] = useState('');
    const [attachmentFile, setAttachmentFile] = useState<File | null>(null);

    const isOwner = !current || !current.accessRole || current.accessRole === 'OWNER';
    const canEdit = !current || ((isOwner || current.accessRole === 'EDITOR') && itemKey !== null);
    const shared = current ? describeSharedAccess(current, session.user.email, collections) : null;
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
                    // Show the access-specific message directly (both languages);
                    // fall back to the generic decryption error otherwise.
                    setError(/^(Для вас|Ви не член|You have|You are not)/.test((e as Error).message)
                        ? (e as Error).message
                        : tr('Не вдалося розшифрувати запис (ключ не підходить).', 'Could not decrypt the item (key does not match).'));
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
        setHibpStatus({ kind: 'checking', message: tr('Перевіряю…', 'Checking…') });
        const timer = window.setTimeout(() => {
            hibpBreachCount(fields.password).then((count) => {
                if (cancelled) return;
                setHibpStatus(count === 0
                    ? { kind: 'clean', message: tr('Не знайдено у відомих витоках.', 'Not found in known breaches.') }
                    : { kind: 'breached', message: tr(`Знайдено у витоках ${count.toLocaleString()} разів — змініть пароль!`, `Found in breaches ${count.toLocaleString()} times — change this password!`) });
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

    // Fetch avatars for the users an item is shared with, so the access list
    // shows faces instead of a generic icon (same source as the collection list).
    useEffect(() => {
        const missing = permissions
            .filter((p) => p.granteeType === 'USER')
            .map((p) => p.grantee.toLowerCase())
            .filter((email) => !(email in shareAvatars));
        if (missing.length === 0) return;
        Promise.all(missing.map((email) => api<{ avatarDataUrl: string | null }>(`/api/settings/${encodeURIComponent(email)}/avatar`)
            .then((r) => [email, r.avatarDataUrl] as const)
            .catch(() => [email, null] as const)))
            .then((pairs) => setShareAvatars((prev) => ({ ...prev, ...Object.fromEntries(pairs) })));
    }, [permissions, shareAvatars]);

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

    /** Encrypts the current fields under `key` into the server item payload. */
    async function buildPayload(key: CryptoKey): Promise<Record<string, unknown>> {
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
        return {
            name: fields.name.trim(),
            url: normalizeUrl(fields.url),
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
    }

    /**
     * POSTs a brand-new server-synced item from the current fields and wires up
     * current + itemKey so the dialog transitions into edit mode. Used both by
     * the normal Save path and by share(), which needs a persisted item id
     * before it can attach a permission.
     */
    async function createServerItem(): Promise<{ item: PasswordItem; key: CryptoKey }> {
        const key = itemKey ?? await pmc.generateItemKey();
        const payload = await buildPayload(key);
        payload.wrappedKey = await pmc.wrapItemKey(key, session.keys.publicKey);
        const created = await api<PasswordItem>('/api/vault/items', {
            method: 'POST',
            body: JSON.stringify(payload),
        });
        setItemKey(key);
        setCurrent(created);
        return { item: created, key };
    }

    /** Returns the persisted item + key, creating it first when sharing a
     * brand-new record (internal or external share both need an item id). */
    async function ensurePersistedItem(): Promise<{ item: PasswordItem; key: CryptoKey }> {
        if (current) {
            if (!itemKey) throw new Error(tr('Немає ключа запису — розшифруйте запис перед шерингом.', 'No item key — decrypt the item before sharing.'));
            return { item: current, key: itemKey };
        }
        if (!fields.name.trim() || (fields.secretType === 'LOGIN' && !fields.password)) {
            throw new Error(tr('Спершу заповніть назву та пароль, потім діліться записом.', 'Fill in the name and password first, then share the item.'));
        }
        return createServerItem();
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
            if (fields.sync) {
                let itemId: string;
                if (current && !wasLocal) {
                    // Already on the server (incl. items share() just persisted).
                    await api(`/api/vault/items/${current.id}`, { method: 'PUT', body: JSON.stringify(await buildPayload(key)) });
                    itemId = current.id;
                } else {
                    itemId = (await createServerItem()).item.id;
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
                await saveLocalOnly(await buildPayload(key), key, wasLocal);
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
        if (!current?.attachment || !confirm(tr('Видалити вкладення?', 'Delete the attachment?'))) return;
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
            throw new Error(tr('Shared-запис не може бути local-only.', 'A shared item cannot be local-only.'));
        }
        if (current && !wasLocal) {
            // The sync-mode endpoint refuses an item the server still considers
            // SHARED, so persist the Personal type first. The server rejects
            // that too while any grant/collection remains — surface a clear ask.
            if (current.itemType === 'SHARED') {
                try {
                    await api(`/api/vault/items/${current.id}`, { method: 'PUT', body: JSON.stringify(payload) });
                } catch (e) {
                    if ((e as ApiError).status === 400) {
                        throw new Error(tr('Спершу відкличте всі доступи (і приберіть колекцію), щоб зробити запис локальним.', 'Revoke all access (and remove the collection) before making this item local.'));
                    }
                    throw e;
                }
            }
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
        if (!current || !confirm(tr(`Видалити «${current.name}»?`, `Delete “${current.name}”?`))) {
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
        setCopyLabel(tr(`Скопійовано (${seconds}с)`, `Copied (${seconds}s)`));
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
            if (!context) throw new Error(tr('Браузер не підтримує читання зображення.', 'This browser cannot read the image.'));
            context.drawImage(bitmap, 0, 0);
            bitmap.close();
            const image = context.getImageData(0, 0, canvas.width, canvas.height);
            const decoded = jsQR(image.data, image.width, image.height, { inversionAttempts: 'attemptBoth' });
            if (!decoded) throw new Error(tr('QR-код не знайдено у вибраному файлі.', 'No QR code found in the selected file.'));
            const uri = decoded.data.trim();
            const parsed = new URL(uri);
            if (parsed.protocol !== 'otpauth:' || parsed.hostname.toLowerCase() !== 'totp') {
                throw new Error(tr('QR-код не містить TOTP otpauth URI.', 'The QR code does not contain a TOTP otpauth URI.'));
            }
            // Validate the actual Base32 secret before placing it in the encrypted form.
            pmc.decodeTotpSeed(uri);
            set('totpSeed', uri);
        } catch (e) {
            setError(tr(`Не вдалося імпортувати TOTP QR: ${(e as Error).message}`, `Could not import the TOTP QR: ${(e as Error).message}`));
        }
    }

    async function share() {
        const grantee = (shareForm.principal?.email ?? shareForm.grantee).trim().toLowerCase();
        if (!grantee) {
            return;
        }
        setError(null);
        try {
            // When sharing a brand-new record, persist it first: permissions
            // attach to an existing item id. buildPayload already carries
            // itemType=SHARED because the type select is switched before this.
            const { item: target, key } = await ensurePersistedItem();
            if (shareForm.principal?.type === 'GROUP') {
                const created = await api<Permission>(`/api/vault/items/${target.id}/permissions`, {
                    method: 'POST', body: JSON.stringify({ granteeType: 'GROUP', grantee,
                        directorySubjectId: shareForm.principal.id, role: shareForm.role }),
                });
                setError(created.warning ?? tr('Групу додано. Видайте ключі доступним учасникам кнопкою Provision.', 'Group added. Grant keys to available members with the Provision button.'));
                setShareForm({ grantee: '', role: shareForm.role, principal: null });
                setPermissions(await api<Permission[]>(`/api/vault/items/${target.id}/permissions`));
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
                wrappedKey: await pmc.wrapItemKey(key, recipientKey),
            };
            const created = await api<Permission>(`/api/vault/items/${target.id}/permissions`, {
                method: 'POST',
                body: JSON.stringify(body),
            });
            if (created.warning) {
                setError(created.warning);
            }
            setShareForm({ grantee: '', role: shareForm.role, principal: null });
            setCurrent({ ...target, itemType: 'SHARED' });
            set('type', 'SHARED');
            setPermissions(await api<Permission[]>(`/api/vault/items/${target.id}/permissions`));
        } catch (e) {
            setError((e as Error).message);
        }
    }


    /**
     * Changes an existing grant's role without revoking it. A role that carries
     * password access needs the item key wrapped for the recipient again — the
     * server never sees the key, so the re-wrap happens here.
     */
    async function changeRole(permission: Permission, role: Permission['role']) {
        if (!current || role === permission.role) return;
        setError(null);
        try {
            const body: Record<string, unknown> = { role };
            if (permission.granteeType === 'USER') {
                if (!itemKey) throw new Error(tr('Ключ запису недоступний — відкрийте запис ще раз.', 'The item key is unavailable — reopen the item.'));
                const recipient = await api<{ publicKey: string }>(`/api/keys/${encodeURIComponent(permission.grantee)}`);
                body.wrappedKey = await pmc.wrapItemKey(itemKey, await pmc.importPublicKey(recipient.publicKey));
            }
            const updated = await api<Permission>(`/api/vault/items/${current.id}/permissions/${permission.id}`, {
                method: 'PATCH', body: JSON.stringify(body),
            });
            if (updated.warning) setError(updated.warning);
            else if (role === 'PASSKEY_ONLY') {
                // The credential key can only be re-wrapped by a client holding
                // the owner's vault private key *and* allowed to touch passkey
                // material, which means the extension. Until it next syncs the
                // grantee sees nothing, and silence there reads as a failure.
                setError(tr(
                    'Доступ надано. Ключ passkey буде передано отримувачу, коли ваше розширення наступного разу синхронізується (розблокуйте його, якщо воно заблоковане).',
                    'Access granted. The passkey key reaches the recipient the next time your extension syncs — unlock it if it is locked.'));
            }
            setPermissions(await api<Permission[]>(`/api/vault/items/${current.id}/permissions`));
        } catch (e) { setError((e as Error).message); }
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
            if (provisioned.length === 0) { setError(tr('У жодного pending учасника ще немає ключів у vault.', 'None of the pending members have vault keys yet.')); return; }
            await api(`/api/vault/items/${current.id}/permissions/${permission.id}/provision`, {
                method: 'POST', body: JSON.stringify({ members: provisioned }),
            });
            setPermissions(await api<Permission[]>(`/api/vault/items/${current.id}/permissions`));
        } catch (e) { setError((e as Error).message); }
    }

    async function shareExternally() {
        setError(null);
        try {
            const { item: target } = await ensurePersistedItem();
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
            // The server's ceiling applies to the ciphertext, which AES-GCM and
            // Base64 have already inflated by about a third. Saying so here
            // names the problem; the bare 400 that used to come back did not.
            if (encrypted.encryptedPackage.length > MAX_ENCRYPTED_PACKAGE_CHARS) {
                throw new Error(tr(
                    'Запис завеликий для зовнішнього посилання. Скоротіть нотатки або довгі поля (наприклад SSH-ключ) і спробуйте ще раз.',
                    'This record is too large for an external link. Shorten the notes or any long fields (an SSH key, say) and try again.'));
            }
            const created = await api<{ id: string }>(`/api/vault/items/${target.id}/external-shares`, {
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
            setError(tr(`Посилання продовжено до ${new Date(extended.expiresAt).toLocaleString()}${extended.oneTime ? ' (одноразове)' : ''}. URL не змінено.`, `Link extended to ${new Date(extended.expiresAt).toLocaleString()}${extended.oneTime ? ' (one-time)' : ''}. The URL is unchanged.`));
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
                setError(tr(`Не вдалося ротувати ключ, revoke скасовано: ${(e as Error).message}`, `Could not rotate the key; revoke was cancelled: ${(e as Error).message}`));
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
            setError(tr('Версію підставлено у форму — натисніть Save, щоб відновити.', 'Version loaded into the form — press Save to restore it.'));
        } catch {
            setError(tr('Не вдалося розшифрувати цю версію.', 'Could not decrypt this version.'));
        }
    }

    // Sharing only makes sense for a Shared record. Existing grants keep the
    // section visible so the owner can still revoke them — the server refuses
    // to turn a shared item back into a personal one until they are gone.
    // In add mode (current === null) the section shows as soon as Shared is
    // picked; share() then persists the item on the first grant.
    const showShare = isOwner && loaded && current?.syncMode !== 'LOCAL_ONLY'
        && (sharedType || permissions.length > 0);
    // External sharing is a standalone encrypted snapshot, NOT an internal
    // permission grant — the backend accepts it for personal items too. So it
    // must NOT require SHARED type or existing permissions (that coupling hid
    // the "Create link" control for ordinary personal passwords). Show it for
    // any owned, server-synced item (or a new one that will be server-synced);
    // shareExternally() persists a brand-new item first. Local-only is excluded
    // because an external share needs a server-side item id.
    // (current === null || itemKey) hides the control for an existing item whose
    // key could not be decrypted, where generation would fail on click anyway.
    const showExternalShare = isOwner && loaded && fields.sync && current?.syncMode !== 'LOCAL_ONLY'
        && (current === null || itemKey !== null);

    return (
        <>
            <dialog id="item-dialog" ref={dialogRef} onClose={() => onClose(false)}>
                <form id="item-form" onSubmit={save}>
                    <h3 id="dialog-title" className={shared ? `shared-with-me${shared.isViewOnly ? ' view-only' : ''}` : ''}>
                        {current ? current.name : t('addPassword')}
                        {shared && (
                            <span className="badge owner-badge"
                                  title={shared.collectionName
                                      ? t('sharedViaCollectionTooltip', { collection: shared.collectionName, owner: shared.ownerEmail })
                                      : t('sharedByTooltip', { owner: shared.ownerEmail })}>
                                <IconUsers width={11} height={11} /> {t('sharedWithMeBadge')}
                            </span>
                        )}
                        {shared && (shared.isViewOnly
                            ? <span className="badge view-only-badge" title={t('viewOnlyTooltip')}>
                                  <IconLock width={11} height={11} /> {t('viewOnlyBadge')}
                              </span>
                            : <span className="badge can-edit-badge" title={t('canEditTooltip')}>
                                  <IconPencil width={11} height={11} /> {t('canEditBadge')}
                              </span>)}
                    </h3>
                    <label>{t('name')}*
                        <input id="f-name" required maxLength={255} readOnly={!canEdit}
                               value={fields.name} onChange={(e) => set('name', e.target.value)} />
                    </label>
                    <label>URL
                        <input id="f-url" type="text" inputMode="url" maxLength={2048} readOnly={!canEdit}
                               placeholder="url.com" value={fields.url}
                               onChange={(e) => set('url', e.target.value)}
                               onBlur={() => { const n = normalizeUrl(fields.url); if (n && n !== fields.url) set('url', n); }} />
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
                                <span className="hint">{s.label} (~{s.bits} {tr('біт', 'bits')})</span>
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
                    <label>{tr('Шаблон секрету', 'Secret template')}
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
                    {current && <p className="hint">{tr('Шаблон секрету фіксується під час створення запису.', 'The secret template is fixed when the item is created.')}</p>}
                    {fields.secretType === 'CARD' && <>
                        <label>{tr('Номер картки', 'Card number')}
                            <input id="f-card-number" inputMode="numeric" autoComplete="off" readOnly={!canEdit}
                                   value={fields.cardNumber} onChange={(e) => set('cardNumber', e.target.value)} />
                        </label>
                        <label>{tr('Власник картки', 'Cardholder')}
                            <input id="f-card-holder" autoComplete="off" readOnly={!canEdit}
                                   value={fields.cardHolder} onChange={(e) => set('cardHolder', e.target.value)} />
                        </label>
                        <div className="row">
                            <label>{tr('Термін дії', 'Expiry')}
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
                        <label>{tr('TOTP seed (Base32 або otpauth URI)', 'TOTP seed (Base32 or otpauth URI)')}
                            <input id="f-totp-seed" type="password" autoComplete="off" readOnly={!canEdit}
                                   value={fields.totpSeed} onChange={(e) => set('totpSeed', e.target.value)} />
                        </label>
                        {canEdit && <label>{tr('Імпортувати TOTP QR', 'Import TOTP QR')}
                            <input id="import-totp-qr" type="file" accept="image/png,image/jpeg,image/webp,image/gif"
                                   onChange={importTotpQr} />
                            <span className="hint">{tr('Зображення обробляється лише у браузері.', 'The image is processed in the browser only.')}</span>
                        </label>}
                        {fields.totpSeed && <div className="row" id="totp-code">
                            <strong>{totpCode || tr('Невірний seed', 'Invalid seed')}</strong>
                            <span className="hint">{tr(`оновлення через ${totpSeconds} с`, `refreshes in ${totpSeconds}s`)}</span>
                            {totpCode && <button type="button" id="copy-totp" className="secondary small"
                                                 onClick={copyTotp}>{t('copy')}</button>}
                            {totpCode && <button type="button" id="show-totp-qr" className="secondary small"
                                                 onClick={toggleTotpQr}>{totpQr ? tr('Приховати QR', 'Hide QR') : tr('Показати QR', 'Show QR')}</button>}
                        </div>}
                        {totpQr && <div className="totp-qr">
                            <img src={totpQr} alt="TOTP QR code" width={160} height={160} />
                            <span className="hint">{tr('Відскануйте в Google Authenticator / Authy, щоб мати той самий код на телефоні.', 'Scan it in Google Authenticator / Authy to get the same code on your phone.')}</span>
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
                        <span>{tr('Зберігати на сервері', 'Store on the server')}</span>
                    </label>
                    <p className="hint" id="sync-hint">
                        {sharedType
                            ? tr('Shared-записи завжди зберігаються на сервері, інакше sharing не працює.', 'Shared items are always stored on the server, otherwise sharing cannot work.')
                            : tr('Вимкнено — запис залишиться тільки в цьому браузері (у зашифрованому вигляді).', 'Off — the item stays in this browser only (encrypted).')}
                    </p>
                    {showShare && (
                        <div id="share-section">
                            <h4>{t('sharedAccess')}</h4>
                            <ul id="permission-list" className="permission-list">
                                {permissions.map((p) => (
                                    <li key={p.id}>
                                        <span className="row">{p.granteeType === 'GROUP'
                                            ? <IconUsers />
                                            : shareAvatars[p.grantee.toLowerCase()]
                                                ? <img className="avatar" src={shareAvatars[p.grantee.toLowerCase()]!} alt="" width={20} height={20} />
                                                : <IconUser />} {p.grantee}
                                            {p.granteeType === 'GROUP' && p.groupVisibleToUsers === false && <span className="badge hidden-group" title={t('groupHiddenTooltip')}>
                                                <IconEyeOff /> {t('groupHiddenBadge')}
                                            </span>}</span>
                                        <span className="row">
                                            <select className="small" aria-label={tr(`Роль для ${p.grantee}`, `Role for ${p.grantee}`)}
                                                    value={p.role} onChange={(e) => changeRole(p, e.target.value as Permission['role'])}>
                                                <option value="VIEWER">Viewer</option>
                                                <option value="EDITOR">Editor</option>
                                                <option value="AUTOFILL_ONLY">Autofill Only (extension)</option>
                                                <option value="PASSKEY_ONLY">Passkey Only (extension autofill, no password)</option>
                                            </select>
                                            {p.granteeType === 'GROUP' && p.status === 'ACTIVE' && <button type="button" className="secondary small" onClick={() => provisionGroup(p)}>{tr('Видати ключі', 'Provision')}</button>}
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
                                    <option value="PASSKEY_ONLY">Passkey Only (extension autofill, no password)</option>
                                </select>
                                <button type="button" id="share-btn" className="secondary" onClick={share}>{t('share')}</button>
                            </div>
                        </div>
                    )}
                    {showExternalShare && <section id="external-share-section">
                        <h4>{t('externalShare')}</h4>
                        <p className="hint">{tr('Окремий зашифрований снапшот; AES-ключ є лише після ', 'A separate encrypted snapshot; the AES key lives only after ')}<code>#</code>{tr(' у посиланні.', ' in the link.')}</p>
                        <div className="row external-share-controls">
                            <label>{tr('Строк дії', 'Expires in')}<select id="external-share-ttl" value={externalTtl} onChange={(e) => setExternalTtl(e.target.value)}>
                                <option value="900">{tr('15 хвилин', '15 minutes')}</option><option value="3600">{tr('1 година', '1 hour')}</option>
                                <option value="86400">{tr('24 години', '24 hours')}</option><option value="604800">{tr('7 днів', '7 days')}</option>
                            </select></label>
                            <label className="checkbox-row"><input id="external-share-one-time" type="checkbox" checked={externalOneTime} onChange={(e) => setExternalOneTime(e.target.checked)} /> {tr('Одноразовий перегляд', 'One-time view')}</label>
                            <button type="button" id="external-share-create" className="secondary" onClick={shareExternally}>{t('createLink')}</button>
                        </div>
                        {externalLink && <div className="external-link"><input readOnly value={externalLink.url} aria-label="External share link" />
                            <button type="button" className={`secondary small${linkCopied ? ' copied' : ''}`} onClick={async () => { await navigator.clipboard.writeText(externalLink.url); setLinkCopied(true); setTimeout(() => setLinkCopied(false), 2000); }}>{linkCopied ? <><IconCheck /> {tr('Скопійовано', 'Copied')}</> : t('copy')}</button>
                            <button type="button" className="secondary small" onClick={extendExternalShare}>{tr('+24 год', '+24 h')}</button>
                            <button type="button" className="secondary small" onClick={revokeExternalShare}>{t('revoke')}</button></div>}
                    </section>}

                    {fields.sync && canEdit && <section id="attachment-section">
                        <h4>{tr('Вкладення', 'Attachment')}</h4>
                        <p className="hint">{tr('Одне вкладення шифрується AES-GCM у браузері та зберігається як непрозорий файл у Google Drive власника. Ліміт розміру не встановлюється застосунком; діють лише квоти й обмеження Google Drive.', 'One attachment is encrypted with AES-GCM in the browser and stored as an opaque file in the owner’s Google Drive. The app sets no size limit; only Google Drive quotas and limits apply.')}</p>
                        {current?.attachment && !attachmentFile && <div className="row attachment-row">
                            <span>{tr('Зашифроване вкладення', 'Encrypted attachment')} · {current.attachment.ciphertextSize.toLocaleString()} B</span>
                            <button type="button" className="secondary small" onClick={downloadAttachment}>{tr('Завантажити', 'Download')}</button>
                            {isOwner && <button type="button" className="secondary small" onClick={deleteAttachment}>{t('delete')}</button>}
                        </div>}
                        {isOwner && <label>{tr('Замінити вкладення', 'Replace attachment')}
                            <input id="f-attachment" type="file" onChange={(event) => setAttachmentFile(event.target.files?.[0] ?? null)} />
                            {attachmentFile && <span className="hint">{tr(`Буде зашифровано і завантажено після Save: ${attachmentFile.name} (${attachmentFile.size.toLocaleString()} B)`, `Will be encrypted and uploaded after Save: ${attachmentFile.name} (${attachmentFile.size.toLocaleString()} B)`)}</span>}
                        </label>}
                        {!isOwner && <p className="hint">{tr('Вкладення недоступне для заміни без прав власника.', 'The attachment cannot be replaced without owner rights.')}</p>}
                    </section>}
                    {!fields.sync && <p className="hint">{tr('Local-only записи виключені з вкладень Drive і серверних адміністраторських операцій.', 'Local-only items are excluded from Drive attachments and server-side admin operations.')}</p>}

                    {current && current.syncMode !== 'LOCAL_ONLY' && itemKey && (
                        <div id="history-section">
                            <button type="button" id="history-btn" className="linklike"
                                    onClick={() => toggleHistory().catch((e) => setError((e as Error).message))}>
                                {versions === null ? tr('Показати історію версій', 'Show version history') : tr('Сховати історію', 'Hide history')}
                            </button>
                            {versions !== null && (
                                <ul id="version-list" className="permission-list">
                                    {versions.length === 0 && <li><span className="hint">{tr('Попередніх версій немає.', 'No previous versions.')}</span></li>}
                                    {versions.map((version) => (
                                        <li key={version.id}>
                                            <span>{new Date(version.replacedAt).toLocaleString()} · {version.name} · {version.replacedBy}</span>
                                            {canEdit && (
                                                <button type="button" className="secondary small"
                                                        onClick={() => restoreVersion(version)}>{tr('Відновити', 'Restore')}</button>
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
                <h3>{tr('Local-only запис', 'Local-only item')}</h3>
                <p>
                    {tr('Цей запис не буде доступний з іншого пристрою і ', 'This item will not be available on another device and ')}
                    <strong>{tr('не може бути відновлений адміністратором', 'cannot be recovered by an administrator')}</strong>
                    {tr('. Він зберігається лише в цьому браузері (у зашифрованому вигляді).', '. It is stored in this browser only (encrypted).')}
                </p>
                <div className="dialog-actions">
                    <button id="warning-cancel" className="secondary" type="button"
                            onClick={() => answerWarning(false)}>{t('cancel')}</button>
                    <button id="warning-confirm" className="danger" type="button"
                            onClick={() => answerWarning(true)}>{tr('Зрозуміло, вимкнути синхронізацію', 'Understood, disable sync')}</button>
                </div>
            </dialog>
        </>
    );
}
