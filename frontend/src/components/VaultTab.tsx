import { useCallback, useEffect, useState } from 'react';
import { api } from './../api';
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
                <button id="add-btn" onClick={() => setDialog({ mode: 'add' })}>+ Add password</button>
            </div>
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
