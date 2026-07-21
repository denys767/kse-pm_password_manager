import { ChangeEvent, useEffect, useState } from 'react';
import { api } from '../api';
import type { FrontendConfig, Settings, SyncMode } from '../types';

interface Props {
    settings: Settings;
    onSaved: (settings: Settings) => void;
    isAdmin: boolean;
    config: FrontendConfig;
}

/** Square-crops and downsizes an uploaded image client-side so the stored data URI stays small. */
async function resizeToAvatar(file: File): Promise<string> {
    const bitmap = await createImageBitmap(file);
    const size = 128;
    const canvas = document.createElement('canvas');
    canvas.width = size; canvas.height = size;
    const ctx = canvas.getContext('2d')!;
    const scale = Math.max(size / bitmap.width, size / bitmap.height);
    const w = bitmap.width * scale; const h = bitmap.height * scale;
    ctx.drawImage(bitmap, (size - w) / 2, (size - h) / 2, w, h);
    return canvas.toDataURL('image/jpeg', 0.85);
}

export function SettingsTab({ settings, onSaved, isAdmin, config }: Props) {
    const [syncMode, setSyncMode] = useState<SyncMode>(settings.defaultSyncMode);
    const [clipboardSeconds, setClipboardSeconds] = useState(settings.clipboardClearSeconds);
    const [avatarDataUrl, setAvatarDataUrl] = useState<string | null>(settings.avatarDataUrl);
    const [status, setStatus] = useState('');

    useEffect(() => { setAvatarDataUrl(settings.avatarDataUrl); }, [settings.avatarDataUrl]);

    async function save(overrides: Partial<Pick<Settings, 'avatarDataUrl'>> = {}) {
        try {
            const saved = await api<Settings>('/api/settings', {
                method: 'PUT',
                body: JSON.stringify({
                    defaultSyncMode: syncMode,
                    clipboardClearSeconds: Number(clipboardSeconds) || 20,
                    avatarDataUrl: 'avatarDataUrl' in overrides ? overrides.avatarDataUrl : avatarDataUrl,
                }),
            });
            onSaved(saved);
            setAvatarDataUrl(saved.avatarDataUrl);
            setStatus('Збережено.');
            setTimeout(() => setStatus(''), 2000);
        } catch (e) {
            setStatus((e as Error).message);
        }
    }

    async function uploadAvatar(event: ChangeEvent<HTMLInputElement>) {
        const file = event.target.files?.[0];
        event.target.value = '';
        if (!file) return;
        try {
            const dataUrl = await resizeToAvatar(file);
            setAvatarDataUrl(dataUrl);
            await save({ avatarDataUrl: dataUrl });
        } catch (e) {
            setStatus((e as Error).message);
        }
    }

    return (
        <section id="tab-settings" className="tab-panel">
            <div className="card narrow">
                <h3>Налаштування</h3>
                <label>Аватар
                    <div className="row">
                        {avatarDataUrl
                            ? <img className="avatar" src={avatarDataUrl} alt="" width={48} height={48} />
                            : <span className="avatar" style={{ width: 48, height: 48 }}>?</span>}
                        <input id="setting-avatar" type="file" accept="image/*" onChange={uploadAvatar} />
                        {avatarDataUrl && <button type="button" className="secondary small"
                                                  onClick={() => { setAvatarDataUrl(null); void save({ avatarDataUrl: null }); }}>Видалити</button>}
                    </div>
                </label>
                <p className="hint">Показується в топбарі й учасникам ваших колекцій. Обрізається до квадрата локально в браузері.</p>
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
                <button id="save-settings-btn" onClick={() => save()}>Save</button>
                <p id="settings-status" className="hint">{status}</p>
            </div>
            {config.authMode === 'oidc' && (
                <div className="card narrow" style={{ marginTop: 18 }}>
                    <h3>Обліковий запис</h3>
                    <p className="hint">
                        Passkey/біометрію (додати, змінити, видалити), сесії входу та профіль Google
                        керуєш не тут, а в Keycloak Account Console — окремій сторінці поза
                        застосунком.
                    </p>
                    <a id="account-console-btn" href={`${config.keycloakUrl}/realms/${encodeURIComponent(config.realm ?? '')}/account/`}
                       target="_blank" rel="noopener noreferrer">
                        <button type="button">Відкрити Account Console</button>
                    </a>
                </div>
            )}
            {isAdmin && <GroupAllowlistCard />}
        </section>
    );
}

/**
 * A Keycloak group only shows up in the Collections "managed group" selector once
 * it's both a real Keycloak group AND allowlisted here — this card manages the
 * allowlist half, reading real group names straight from Keycloak so admins don't
 * have to type them blind or use curl against /api/admin/collection-groups.
 */
function GroupAllowlistCard() {
    const [keycloakGroups, setKeycloakGroups] = useState<string[]>([]);
    const [allowed, setAllowed] = useState<string[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState<string | null>(null);

    async function refresh() {
        try {
            const [kc, allow] = await Promise.all([
                api<string[]>('/api/admin/collection-groups/keycloak'),
                api<string[]>('/api/admin/collection-groups'),
            ]);
            setKeycloakGroups(kc);
            setAllowed(allow);
            setError(null);
        } catch (e) {
            setError((e as Error).message);
        }
    }

    useEffect(() => { void refresh(); }, []);

    async function toggle(group: string, isAllowed: boolean) {
        setBusy(group);
        try {
            if (isAllowed) {
                await api(`/api/admin/collection-groups/${encodeURIComponent(group)}`, { method: 'DELETE' });
            } else {
                await api('/api/admin/collection-groups', { method: 'POST', body: JSON.stringify({ groupName: group }) });
            }
            await refresh();
        } catch (e) {
            setError((e as Error).message);
        } finally {
            setBusy(null);
        }
    }

    const allowedSet = new Set(allowed.map((g) => g.toLowerCase()));
    // Allowlisted names that no longer match a live Keycloak group (renamed/deleted) still need to be visible so they can be removed.
    const orphaned = allowed.filter((g) => !keycloakGroups.some((k) => k.toLowerCase() === g.toLowerCase()));
    const rows = [...keycloakGroups, ...orphaned];

    return (
        <div className="card narrow" style={{ marginTop: 18 }}>
            <h3>Keycloak-групи для колекцій</h3>
            <p className="hint">
                Селектор "managed group" у Colections показує лише групи, позначені тут — вони мають
                фізично існувати в Keycloak. Google Workspace-групи тут не з'являються автоматично:
                спершу створіть відповідну групу в Keycloak Admin Console (Groups) з тими самими
                учасниками, і лише тоді вона зʼявиться в списку нижче.
            </p>
            {error && <p className="error">{error}</p>}
            {rows.length === 0 && <p className="hint">У Keycloak ще немає жодної групи.</p>}
            <ul className="permission-list">
                {rows.map((group) => {
                    const isAllowed = allowedSet.has(group.toLowerCase());
                    const exists = keycloakGroups.some((k) => k.toLowerCase() === group.toLowerCase());
                    return (
                        <li key={group} className="row" style={{ justifyContent: 'space-between' }}>
                            <span>{group}{!exists && <small className="hint"> (видалено з Keycloak)</small>}</span>
                            <label className="row" style={{ margin: 0 }}>
                                <input type="checkbox" checked={isAllowed} disabled={busy === group}
                                       onChange={() => toggle(group, isAllowed)} />
                                Дозволено для колекцій
                            </label>
                        </li>
                    );
                })}
            </ul>
        </div>
    );
}
