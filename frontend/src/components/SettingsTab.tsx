import { ChangeEvent, useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { verifyPassphrase } from '../auth';
import { isWebAuthnSupported, registerVaultWebAuthn, removeVaultWebAuthn, vaultWebAuthnEnrolledAt } from '../webauthnVault';
import type { FrontendConfig, Me, Settings, SyncMode } from '../types';
import { useI18n } from '../i18n';
import { useTheme } from '../theme';
import { TOS_SECTIONS } from '../termsOfService';
import { EULA_SECTIONS } from '../eula';

interface Props {
    settings: Settings;
    onSaved: (settings: Settings) => void;
    isAdmin: boolean;
    config: FrontendConfig;
    user: Me;
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

export function SettingsTab({ settings, onSaved, config, user }: Props) {
    const { t, language } = useI18n();
    const tr = (uk: string, en: string) => (language === 'uk' ? uk : en);
    const { preference, setPreference } = useTheme();
    const [syncMode, setSyncMode] = useState<SyncMode>(settings.defaultSyncMode);
    const [clipboardSeconds, setClipboardSeconds] = useState(settings.clipboardClearSeconds);
    const [avatarDataUrl, setAvatarDataUrl] = useState<string | null>(settings.avatarDataUrl);
    const [status, setStatus] = useState('');
    const [webauthnEnrolledAt, setWebauthnEnrolledAt] = useState<string | null>(() => vaultWebAuthnEnrolledAt(user.email));
    const [webauthnPass, setWebauthnPass] = useState('');
    const [webauthnBusy, setWebauthnBusy] = useState(false);
    const [webauthnStatus, setWebauthnStatus] = useState('');
    const tosDialogRef = useRef<HTMLDialogElement>(null);
    const eulaDialogRef = useRef<HTMLDialogElement>(null);

    useEffect(() => { setAvatarDataUrl(settings.avatarDataUrl); }, [settings.avatarDataUrl]);
    useEffect(() => { setWebauthnEnrolledAt(vaultWebAuthnEnrolledAt(user.email)); }, [user.email]);

    async function enableWebauthn() {
        setWebauthnStatus('');
        if (!webauthnPass) { setWebauthnStatus(t('vaultWebauthnWrongPass')); return; }
        setWebauthnBusy(true);
        try {
            if (!await verifyPassphrase(webauthnPass)) { setWebauthnStatus(t('vaultWebauthnWrongPass')); return; }
            await registerVaultWebAuthn(user, webauthnPass);
            setWebauthnPass('');
            setWebauthnEnrolledAt(vaultWebAuthnEnrolledAt(user.email));
            setWebauthnStatus(t('vaultWebauthnEnabledOk'));
        } catch (e) {
            setWebauthnStatus((e as Error).message);
        } finally {
            setWebauthnBusy(false);
        }
    }

    function disableWebauthn() {
        removeVaultWebAuthn(user.email);
        setWebauthnEnrolledAt(null);
        setWebauthnStatus(t('vaultWebauthnDisabled'));
    }

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
            setStatus(tr('Збережено.', 'Saved.'));
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
                <label>{tr('Аватар', 'Avatar')}
                    <div className="row">
                        {avatarDataUrl
                            ? <img className="avatar large" src={avatarDataUrl} alt="" />
                            : <span className="avatar large">?</span>}
                        <input id="setting-avatar" type="file" accept="image/*" onChange={uploadAvatar} />
                        {avatarDataUrl && <button type="button" className="secondary small"
                                                  onClick={() => { setAvatarDataUrl(null); void save({ avatarDataUrl: null }); }}>{t('delete')}</button>}
                    </div>
                </label>
                <p className="hint">{tr('Показується в топбарі й учасникам ваших колекцій. Обрізається до квадрата локально в браузері.', 'Shown in the top bar and to members of your collections. Cropped to a square locally in the browser.')}</p>
                <label>{tr('Режим збереження за замовчуванням', 'Default storage mode')}
                    <select id="setting-sync" value={syncMode}
                            onChange={(e) => setSyncMode(e.target.value as SyncMode)}>
                        <option value="SERVER_SYNCED">{tr('Зберігати на сервері', 'Store on the server')}</option>
                        <option value="LOCAL_ONLY">Local-only</option>
                    </select>
                </label>
                <label>{tr('Очищати clipboard через (секунд)', 'Clear clipboard after (seconds)')}
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
            {config.authMode === 'oidc' && (
                <div id="vault-webauthn-card" className="card narrow" style={{ marginTop: 18 }}>
                    <h3>{t('vaultWebauthn')}</h3>
                    <p className="hint">{t('vaultWebauthnDesc')}</p>
                    {!isWebAuthnSupported()
                        ? <p className="hint">{t('vaultWebauthnUnsupported')}</p>
                        : webauthnEnrolledAt
                            ? <>
                                <p className="hint">{t('vaultWebauthnEnrolled', { date: new Date(webauthnEnrolledAt).toLocaleDateString(language === 'uk' ? 'uk-UA' : 'en-US') })}</p>
                                <button id="webauthn-disable-btn" type="button" className="secondary" onClick={disableWebauthn}>{t('vaultWebauthnDisable')}</button>
                            </>
                            : <>
                                <label>{t('vaultWebauthnPassLabel')}
                                    <input id="webauthn-passphrase" type="password" autoComplete="current-password"
                                           value={webauthnPass} onChange={(e) => setWebauthnPass(e.target.value)} />
                                </label>
                                <button id="webauthn-enable-btn" type="button" disabled={webauthnBusy} onClick={enableWebauthn}>
                                    {webauthnBusy ? '…' : t('vaultWebauthnEnable')}
                                </button>
                            </>}
                    {webauthnStatus && <p id="webauthn-status" className="hint">{webauthnStatus}</p>}
                </div>
            )}
            {/* Google Workspace is the source of groups; there is no local/Keycloak allowlist. */}
            <div className="card narrow" style={{ marginTop: 18 }}>
                <h3>{t('legal')}</h3>
                <p className="hint">{t('legalDescription')}</p>
                <div className="row">
                    <button type="button" className="secondary" onClick={() => tosDialogRef.current?.showModal()}>{t('viewTos')}</button>
                    <button type="button" className="secondary" onClick={() => eulaDialogRef.current?.showModal()}>{t('viewEula')}</button>
                </div>
            </div>
            <dialog id="settings-tos-dialog" ref={tosDialogRef}>
                <h3>{t('tosDialogTitle')}</h3>
                <div className="tos-text">
                    {TOS_SECTIONS.map((section) => <div key={section.title}>
                        <h4>{section.title}</h4>
                        {section.paragraphs.map((p, i) => <p key={i}>{p}</p>)}
                    </div>)}
                </div>
                <div className="dialog-actions">
                    <span className="spacer" />
                    <button type="button" onClick={() => tosDialogRef.current?.close()}>{t('tosClose')}</button>
                </div>
            </dialog>
            <dialog id="settings-eula-dialog" ref={eulaDialogRef}>
                <h3>{t('eulaDialogTitle')}</h3>
                <div className="tos-text">
                    {EULA_SECTIONS.map((section) => <div key={section.title.en}>
                        <h4>{section.title[language]}</h4>
                        {section.paragraphs.map((p, i) => <p key={i}>{p[language]}</p>)}
                    </div>)}
                </div>
                <div className="dialog-actions">
                    <span className="spacer" />
                    <button type="button" onClick={() => eulaDialogRef.current?.close()}>{t('eulaClose')}</button>
                </div>
            </dialog>
        </section>
    );
}
