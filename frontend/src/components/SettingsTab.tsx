import { useState } from 'react';
import { api } from '../api';
import type { Settings, SyncMode } from '../types';

interface Props {
    settings: Settings;
    onSaved: (settings: Settings) => void;
}

export function SettingsTab({ settings, onSaved }: Props) {
    const [syncMode, setSyncMode] = useState<SyncMode>(settings.defaultSyncMode);
    const [clipboardSeconds, setClipboardSeconds] = useState(settings.clipboardClearSeconds);
    const [status, setStatus] = useState('');

    async function save() {
        try {
            const saved = await api<Settings>('/api/settings', {
                method: 'PUT',
                body: JSON.stringify({
                    defaultSyncMode: syncMode,
                    clipboardClearSeconds: Number(clipboardSeconds) || 20,
                }),
            });
            onSaved(saved);
            setStatus('Збережено.');
            setTimeout(() => setStatus(''), 2000);
        } catch (e) {
            setStatus((e as Error).message);
        }
    }

    return (
        <section id="tab-settings" className="tab-panel">
            <div className="card narrow">
                <h3>Налаштування</h3>
                <label>Режим збереження за замовчуванням
                    <select id="setting-sync" value={syncMode}
                            onChange={(e) => setSyncMode(e.target.value as SyncMode)}>
                        <option value="SERVER_SYNCED">Зберігати на сервері</option>
                        <option value="LOCAL_ONLY">Local-only</option>
                    </select>
                </label>
                <label>Очищати clipboard через (секунд)
                    <input id="setting-clipboard" type="number" min={5} max={120}
                           value={clipboardSeconds}
                           onChange={(e) => setClipboardSeconds(Number(e.target.value))} />
                </label>
                <button id="save-settings-btn" onClick={save}>Save</button>
                <p id="settings-status" className="hint">{status}</p>
            </div>
        </section>
    );
}
