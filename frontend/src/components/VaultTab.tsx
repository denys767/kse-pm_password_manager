import { ChangeEvent, useCallback, useEffect, useRef, useState } from 'react';
import { api } from './../api';
import * as pmc from '../crypto';
import { previewCsv, toCsv, CsvPreview, CsvRow } from '../csv';
import { emptyPayload, parsePayload, serializePayload } from '../payload';
import { unwrapItemKeyFor } from '../itemKeys';
import { loadLocalItems } from '../localItems';
import { ItemDialog } from './ItemDialog';
import { IconFolder, IconLock, IconPencil, IconUsers } from './Icons';
import { parseTags, collectTags } from '../tags';
import { useI18n } from '../i18n';
import { describeSharedAccess } from '../sharedAccess';
import type { Session } from '../App';
import type { Collection, PasswordItem, Settings } from '../types';

interface Props {
    session: Session;
    settings: Settings;
    collections: Collection[];
    openItemId?: string | null;
    onItemOpened?: () => void;
    tagFilter?: string | null;
    onClearTagFilter?: () => void;
}

type DialogState = { mode: 'add' } | { mode: 'edit'; item: PasswordItem } | null;

export function VaultTab({ session, settings, collections, openItemId, onItemOpened, tagFilter, onClearTagFilter }: Props) {
    const { t, language } = useI18n();
    const tr = (uk: string, en: string) => (language === 'uk' ? uk : en);
    const [serverItems, setServerItems] = useState<PasswordItem[]>([]);
    const [localItems, setLocalItems] = useState<PasswordItem[]>([]);
    const [search, setSearch] = useState('');
    const [dialog, setDialog] = useState<DialogState>(null);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState<string | null>(null);
    const [csvPreview, setCsvPreview] = useState<CsvPreview | null>(null);
    const importInput = useRef<HTMLInputElement>(null);

    const refresh = useCallback(async () => {
        try {
            setServerItems(await api<PasswordItem[]>('/api/vault/items'));
            setLocalItems(loadLocalItems(session.user.email));
            setError(null);
        } catch (e) {
            setError((e as Error).message);
        }
    }, [session.user.email]);

    useEffect(() => {
        refresh();
    }, [refresh]);

    /** Decrypts every readable item and downloads a plaintext CSV. */
    async function exportCsv() {
        setBusy(tr('Експортую…', 'Exporting…'));
        setError(null);
        try {
            const rows: CsvRow[] = [];
            let skipped = 0;
            for (const item of [...serverItems, ...localItems]) {
                try {
                    const key = await unwrapItemKeyFor(item, collections, session.keys);
                    const payload = parsePayload(item.encryptedNotes
                        ? await pmc.decryptField(key, item.encryptedNotes, item.notesIv!)
                        : '');
                    rows.push({
                        version: '4',
                        action: 'create',
                        id: item.id,
                        updatedAt: item.updatedAt,
                        name: item.name,
                        secretType: item.type ?? 'LOGIN',
                        url: item.url || '',
                        username: item.username || '',
                        password: await pmc.decryptField(key, item.encryptedPassword, item.passwordIv),
                        notes: payload.notes,
                        tags: item.tags || '',
                        apiKey: payload.apiKey,
                        apiSecret: payload.apiSecret,
                        sshPrivateKey: payload.sshPrivateKey,
                        sshPublicKey: payload.sshPublicKey,
                        databaseType: payload.databaseType,
                        databaseHost: payload.databaseHost,
                        databasePort: payload.databasePort,
                        databaseName: payload.databaseName,
                        databaseUsername: payload.databaseUsername,
                        databasePassword: payload.databasePassword,
                        cardNumber: payload.cardNumber,
                        cardCvv: payload.cardCvv,
                        cardHolder: payload.cardHolder,
                        cardExpiry: payload.cardExpiry,
                        totpSeed: payload.totpSeed,
                        // Permission wrappers and Drive attachment ciphertext are
                        // intentionally not emitted as plaintext CSV columns.
                        permissions: '', fileName: '', fileData: '',
                    });
                } catch {
                    skipped++;
                }
            }
            const blob = new Blob([toCsv(rows)], { type: 'text/csv;charset=utf-8' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = 'kse-pm-export.csv';
            link.click();
            URL.revokeObjectURL(link.href);
            if (skipped > 0) {
                setError(tr(`Пропущено ${skipped} записів без доступного ключа.`, `Skipped ${skipped} items without an available key.`));
            }
        } finally {
            setBusy(null);
        }
    }

    /** Parse locally first. A deliberate second confirmation makes destructive
     * v4 update/delete actions visible before encrypted commands are sent. */
    async function importCsv(event: ChangeEvent<HTMLInputElement>) {
        const file = event.target.files?.[0];
        event.target.value = '';
        if (!file) {
            return;
        }
        setError(null);
        try {
            const preview = previewCsv(await file.text());
            setCsvPreview(preview);
            if (preview.rows.length === 0) setError(tr('У файлі не знайдено записів для імпорту.', 'No items to import were found in the file.'));
        } catch (e) {
            setError(tr(`Імпорт: ${(e as Error).message}`, `Import: ${(e as Error).message}`));
        }
    }

    async function commitCsvImport() {
        if (!csvPreview) return;
        if (csvPreview.warnings.length) {
            setError(csvPreview.warnings.join(' '));
            return;
        }
        setBusy(tr('Шифрую та імпортую…', 'Encrypting and importing…')); setError(null);
        try {
            const commands = [];
            for (const row of csvPreview.rows) commands.push(await csvCommand(row));
            // Preview is also server-side: it checks access and optimistic
            // versions immediately before one transactional commit.
            await api('/api/vault/imports/preview', { method: 'POST', body: JSON.stringify({ commands }) });
            await api('/api/vault/imports/commit', { method: 'POST', body: JSON.stringify({ commands }) });
            setCsvPreview(null);
            await refresh();
        } catch (e) { setError(tr(`Імпорт: ${(e as Error).message}`, `Import: ${(e as Error).message}`)); }
        finally { setBusy(null); }
    }

    async function csvCommand(row: CsvRow) {
        if (row.action === 'delete') {
            return { action: 'DELETE', itemId: row.id, expectedUpdatedAt: row.updatedAt };
        }
        const existing = row.action === 'update'
            ? serverItems.find((item) => item.id === row.id) : undefined;
        if (row.action === 'update' && !existing) {
            throw new Error(tr(`Запис ${row.id} недоступний для update`, `Item ${row.id} is not available for update`));
        }
        const key = existing ? await unwrapItemKeyFor(existing, collections, session.keys) : await pmc.generateItemKey();
        const password = await pmc.encryptField(key, row.password);
        const notes = await pmc.encryptField(key, serializePayload({
            ...emptyPayload(), notes: row.notes, apiKey: row.apiKey, apiSecret: row.apiSecret,
            sshPrivateKey: row.sshPrivateKey, sshPublicKey: row.sshPublicKey,
            databaseType: row.databaseType, databaseHost: row.databaseHost, databasePort: row.databasePort,
            databaseName: row.databaseName, databaseUsername: row.databaseUsername, databasePassword: row.databasePassword,
            cardNumber: row.cardNumber, cardCvv: row.cardCvv, cardHolder: row.cardHolder,
            cardExpiry: row.cardExpiry, totpSeed: row.totpSeed,
        }));
        return {
            action: row.action.toUpperCase(), itemId: row.action === 'update' ? row.id : null,
            expectedUpdatedAt: row.action === 'update' ? row.updatedAt : null,
            item: {
                name: row.name, url: row.url || null, username: row.username || null,
                encryptedPassword: password.ct, passwordIv: password.iv, encryptedNotes: notes.ct, notesIv: notes.iv,
                tags: row.tags || null, type: row.secretType,
                itemType: existing?.itemType ?? 'PERSONAL', syncMode: 'SERVER_SYNCED',
                wrappedKey: existing ? null : await pmc.wrapItemKey(key, session.keys.publicKey),
            },
        };
    }

    const query = search.trim().toLowerCase();
    const allItems = [...serverItems, ...localItems];
    const availableTags = collectTags(allItems.map((item) => item.tags)).map((tag) => tag.name);
    const items = allItems
        .filter((item) => !tagFilter || parseTags(item.tags).some((tag) => tag.localeCompare(tagFilter, undefined, { sensitivity: 'accent' }) === 0))
        .filter((item) => !query || [item.name, item.url, item.username, item.tags]
            .some((v) => v && v.toLowerCase().includes(query)))
        .sort((a, b) => a.name.localeCompare(b.name));

    useEffect(() => {
        if (!openItemId) return;
        const item = [...serverItems, ...localItems].find((candidate) => candidate.id === openItemId);
        if (item) {
            setDialog({ mode: 'edit', item });
            onItemOpened?.();
        }
    }, [localItems, onItemOpened, openItemId, serverItems]);

    return (
        <section id="tab-vault" className="tab-panel">
            <div className="toolbar">
                <input id="search" type="search" placeholder={t('search')}
                       value={search} onChange={(e) => setSearch(e.target.value)} />
                <button id="export-btn" className="secondary" disabled={busy !== null}
                        onClick={() => exportCsv()}>{t('exportCsv')}</button>
                <button id="import-btn" className="secondary" disabled={busy !== null}
                        onClick={() => importInput.current?.click()}>{t('importCsv')}</button>
                <input ref={importInput} type="file" accept=".csv,text/csv" hidden
                       onChange={importCsv} />
                <button id="add-btn" onClick={() => setDialog({ mode: 'add' })}>{t('addSecret')}</button>
            </div>
            {tagFilter && <div className="active-tag-filter"><span>{t('activeTag')} <strong>{tagFilter}</strong></span><button type="button" className="secondary small" onClick={onClearTagFilter}>{t('clear')}</button></div>}
            {busy && <p className="hint">{busy}</p>}
            {error && <p className="error">{error}</p>}
            {csvPreview && <section className="csv-preview" aria-live="polite">
                <strong>CSV v4 preview:</strong> {csvPreview.createCount} create, {csvPreview.updateCount} update, {csvPreview.deleteCount} delete.
                {csvPreview.warnings.map((warning) => <p key={warning} className="error">{warning}</p>)}
                <button type="button" disabled={busy !== null || csvPreview.warnings.length > 0}
                    onClick={() => void commitCsvImport()}>{tr('Підтвердити імпорт', 'Confirm import')}</button>{' '}
                <button type="button" className="secondary" disabled={busy !== null} onClick={() => setCsvPreview(null)}>{t('cancel')}</button>
            </section>}
            <ul id="item-list" className="item-list">
                {items.map((item) => {
                    const shared = describeSharedAccess(item, session.user.email, collections);
                    return (
                    <li key={item.id} className={shared ? `shared-with-me${shared.isViewOnly ? ' view-only' : ''}` : ''}
                        onClick={() => setDialog({ mode: 'edit', item })}>
                        <div>
                            <strong>{item.name}</strong>
                            <span className="badge">{(item.type ?? 'LOGIN').toLowerCase().replace('_', ' ')}</span>
                            {/* Shared-with-me rows carry the owner badge below; the raw tag would duplicate it. */}
                            {item.itemType === 'SHARED' && !shared && <span className="badge shared">shared</span>}
                            {item.syncMode === 'LOCAL_ONLY' && <span className="badge local">local-only</span>}
                            {item.collectionId && (
                                <span className="badge shared">
                                    <IconFolder width={11} height={11} /> {collections.find((c) => c.id === item.collectionId)?.name ?? 'collection'}
                                </span>
                            )}
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
                            <div className="item-meta">
                                {[item.username, item.url].filter(Boolean).join(' · ')}
                            </div>
                        </div>
                        <button className="secondary small">{t('open')}</button>
                    </li>
                    );
                })}
            </ul>
            {items.length === 0 && (
                <p id="empty-state" className="hint">{t('emptyVault')}</p>
            )}
            {dialog && (
                <ItemDialog
                    session={session}
                    settings={settings}
                    collections={collections}
                    item={dialog.mode === 'edit' ? dialog.item : null}
                    availableTags={availableTags}
                    onClose={async (changed) => {
                        setDialog(null);
                        if (changed) {
                            await refresh();
                        }
                    }}
                />
            )}
        </section>
    );
}
