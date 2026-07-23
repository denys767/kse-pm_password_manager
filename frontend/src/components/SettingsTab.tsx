import { ChangeEvent, useEffect, useState } from 'react';
import { api } from '../api';
import type { FrontendConfig, Settings, SyncMode } from '../types';
import { useI18n } from '../i18n';
import { useTheme } from '../theme';

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

export function SettingsTab({ settings, onSaved, config }: Props) {
    const { t } = useI18n();
    const { preference, setPreference } = useTheme();
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
                <h3>{t('settings')}</h3>
                <label>{t('theme')}
                    <select id="setting-theme" value={preference} onChange={(e) => setPreference(e.target.value as 'system' | 'light' | 'dark')}>
                        <option value="system">{t('themeSystem')}</option><option value="light">{t('themeLight')}</option><option value="dark">{t('themeDark')}</option>
                    </select>
                </label>
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
                <button id="save-settings-btn" onClick={() => save()}>{t('save')}</button>
                <p id="settings-status" className="hint">{status}</p>
            </div>
            {config.authMode === 'oidc' && (
                <div className="card narrow" style={{ marginTop: 18 }}>
                    <h3>{t('account')}</h3>
                    <p className="hint">{t('accountDescription')}</p>
                    <p id="passkey-optional-hint" className="hint">{t('passkeyOptionalHint')}</p>
                    <a id="account-console-btn" href={`${config.keycloakUrl}/realms/${encodeURIComponent(config.realm ?? '')}/account/`}
                       target="_blank" rel="noopener noreferrer">
                        <button type="button">{t('accountConsole')}</button>
                    </a>
                </div>
            )}
            {/* Google Workspace is the source of groups; there is no local/Keycloak allowlist. */}
        </section>
    );
}
