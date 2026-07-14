import { ChangeEvent, useCallback, useEffect, useRef, useState } from 'react';
import { api } from './../api';
import * as pmc from '../crypto';
import { parseCsv, toCsv, CsvRow } from '../csv';
import { loadLocalItems } from '../localItems';
import { ItemDialog } from './ItemDialog';
import type { Session } from '../App';
import type { PasswordItem, Settings } from '../types';

interface Props {
    session: Session;
    settings: Settings;
}

type DialogState = { mode: 'add' } | { mode: 'edit'; item: PasswordItem } | null;

export function VaultTab({ session, settings }: Props) {
    const [serverItems, setServerItems] = useState<PasswordItem[]>([]);
    const [localItems, setLocalItems] = useState<PasswordItem[]>([]);
    const [search, setSearch] = useState('');
    const [dialog, setDialog] = useState<DialogState>(null);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState<string | null>(null);
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
        setBusy('Експортую…');
        setError(null);
        try {
            const rows: CsvRow[] = [];
            let skipped = 0;
            for (const item of [...serverItems, ...localItems]) {
                try {
                    const key = item.syncMode === 'LOCAL_ONLY'
                        ? await pmc.unwrapItemKeyWithKek(item.kekWrappedKey!.ct, item.kekWrappedKey!.iv, session.keys.kek)
                        : await pmc.unwrapItemKey(item.wrappedKey!, session.keys.privateKey);
                    rows.push({
                        name: item.name,
                        url: item.url || '',
                        username: item.username || '',
                        password: await pmc.decryptField(key, item.encryptedPassword, item.passwordIv),
                        notes: item.encryptedNotes
                            ? await pmc.decryptField(key, item.encryptedNotes, item.notesIv!)
                            : '',
                        tags: item.tags || '',
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
                setError(`Пропущено ${skipped} записів без доступного ключа.`);
            }
        } finally {
            setBusy(null);
        }
    }

    /** Imports CSV rows as personal server-synced items, each with its own key. */
    async function importCsv(event: ChangeEvent<HTMLInputElement>) {
        const file = event.target.files?.[0];
        event.target.value = '';
        if (!file) {
            return;
        }
        setBusy('Імпортую…');
        setError(null);
        try {
            const rows = parseCsv(await file.text());
            let imported = 0;
            for (const row of rows) {
                const key = await pmc.generateItemKey();
                const password = await pmc.encryptField(key, row.password);
                const notes = row.notes ? await pmc.encryptField(key, row.notes) : null;
                await api('/api/vault/items', {
                    method: 'POST',
                    body: JSON.stringify({
                        name: row.name,
                        url: row.url || null,
                        username: row.username || null,
                        encryptedPassword: password.ct,
                        passwordIv: password.iv,
                        encryptedNotes: notes ? notes.ct : null,
                        notesIv: notes ? notes.iv : null,
                        tags: row.tags || null,
                        itemType: 'PERSONAL',
                        syncMode: 'SERVER_SYNCED',
                        wrappedKey: await pmc.wrapItemKey(key, session.keys.publicKey),
                    }),
                });
                imported++;
            }
            await refresh();
            setError(imported > 0 ? null : 'У файлі не знайдено записів для імпорту.');
        } catch (e) {
            setError(`Імпорт: ${(e as Error).message}`);
        } finally {
            setBusy(null);
        }
    }

    const query = search.trim().toLowerCase();
    const items = [...serverItems, ...localItems]
        .filter((item) => !query || [item.name, item.url, item.username, item.tags]
            .some((v) => v && v.toLowerCase().includes(query)))
        .sort((a, b) => a.name.localeCompare(b.name));

    return (
        <section id="tab-vault" className="tab-panel">
            <div className="toolbar">
                <input id="search" type="search" placeholder="Пошук за назвою, URL, тегами…"
                       value={search} onChange={(e) => setSearch(e.target.value)} />
                <button id="export-btn" className="secondary" disabled={busy !== null}
                        onClick={() => exportCsv()}>Export CSV</button>
                <button id="import-btn" className="secondary" disabled={busy !== null}
                        onClick={() => importInput.current?.click()}>Import CSV</button>
                <input ref={importInput} type="file" accept=".csv,text/csv" hidden
                       onChange={importCsv} />
                <button id="add-btn" onClick={() => setDialog({ mode: 'add' })}>+ Add password</button>
            </div>
            {busy && <p className="hint">{busy}</p>}
            {error && <p className="error">{error}</p>}
            <ul id="item-list" className="item-list">
                {items.map((item) => (
                    <li key={item.id} onClick={() => setDialog({ mode: 'edit', item })}>
                        <div>
                            <strong>{item.name}</strong>
                            {item.itemType === 'SHARED' && <span className="badge shared">shared</span>}
                            {item.syncMode === 'LOCAL_ONLY' && <span className="badge local">local-only</span>}
                            {item.accessRole && item.accessRole !== 'OWNER'
                                && <span className="badge">{item.accessRole.toLowerCase()}</span>}
                            <div className="item-meta">
                                {[item.username, item.url].filter(Boolean).join(' · ')}
                            </div>
                        </div>
                        <button className="secondary small">Open</button>
                    </li>
                ))}
            </ul>
            {items.length === 0 && (
                <p id="empty-state" className="hint">Vault порожній. Додайте перший пароль.</p>
            )}
            {dialog && (
                <ItemDialog
                    session={session}
                    settings={settings}
                    item={dialog.mode === 'edit' ? dialog.item : null}
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
