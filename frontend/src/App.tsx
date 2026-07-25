import { useCallback, useEffect, useState } from 'react';
import { api } from './api';
import { consumeVaultResetIntent, createVault, fetchConfig, fetchVaultSalt, initOidc, loadOrCreateKeys, oidcLogout, resetVault, setDevIdentity, VaultKeys } from './auth';
import { clearLocalItems } from './localItems';
import { pruneStaleVaultWebAuthn, removeVaultWebAuthn } from './webauthnVault';
import { clearVaultSession, loadVaultSession, saveVaultSession } from './vaultSession';
import { UnlockScreen } from './components/UnlockScreen';
import { VaultTab } from './components/VaultTab';
import { CollectionsTab } from './components/CollectionsTab';
import { AuditTab } from './components/AuditTab';
import { SettingsTab } from './components/SettingsTab';
import { DashboardTab } from './components/DashboardTab';
import { ExternalSharePage } from './components/ExternalSharePage';
import { TagsTab } from './components/TagsTab';
import { AdminTab } from './components/AdminTab';
import { IconActivity, IconCollections, IconDashboard, IconLock, IconSettings, IconTag, IconUsers, IconVault } from './components/Icons';
import { LanguageSwitcher, useI18n } from './i18n';
import type { Collection, FrontendConfig, Me, Settings } from './types';

export interface Session {
    user: Me;
    keys: VaultKeys;
}

type Tab = 'vault' | 'dashboard' | 'collections' | 'tags' | 'audit' | 'admin' | 'settings';

export default function App() {
    const { t, language } = useI18n();
    const tr = (uk: string, en: string) => (language === 'uk' ? uk : en);
    const externalShareMatch = window.location.pathname.match(/^\/share\/([0-9a-f-]{36})$/i);
    if (externalShareMatch) return <ExternalSharePage shareId={externalShareMatch[1]} />;
    const [config, setConfig] = useState<FrontendConfig | null>(null);
    const [oidcReady, setOidcReady] = useState(false);
    const [session, setSession] = useState<Session | null>(null);
    const [collections, setCollections] = useState<Collection[]>([]);
    const [settings, setSettings] = useState<Settings>({
        defaultSyncMode: 'SERVER_SYNCED',
        clipboardClearSeconds: 20,
        avatarDataUrl: null,
    });
    const [tab, setTab] = useState<Tab>('vault');
    const [vaultItemToOpen, setVaultItemToOpen] = useState<string | null>(null);
    const [vaultTagFilter, setVaultTagFilter] = useState<string | null>(null);
    const [fatal, setFatal] = useState<string | null>(null);
    const [bootstrapUser, setBootstrapUser] = useState<Me | null>(null);
    const [hasVault, setHasVault] = useState(true);
    const [resetRequested, setResetRequested] = useState(false);
    // Identifies the current keypair; a passkey enrolment made for a different
    // one wraps a passphrase this vault no longer accepts.
    const [vaultSalt, setVaultSalt] = useState<string | null>(null);

    useEffect(() => {
        fetchConfig()
            .then(async (cfg) => {
                setConfig(cfg);
                if (cfg.authMode === 'oidc') {
                    await initOidc(cfg);
                    const me = await api<Me>('/api/me');
                    setBootstrapUser(me);
                    const resetIntent = consumeVaultResetIntent();
                    setResetRequested(resetIntent);
                    const salt = await fetchVaultSalt();
                    const vaultExists = salt !== null;
                    setHasVault(vaultExists);
                    setVaultSalt(salt);
                    // A vault reset or re-creation may well have happened in
                    // another browser; this is where such an orphan is noticed.
                    pruneStaleVaultWebAuthn(me.email, salt);
                    // Resume an unlock that is still valid instead of asking for
                    // the passphrase again after the Keycloak redirect. A pending
                    // reset must not resume: it is about to replace these keys.
                    if (vaultExists && !resetIntent) {
                        const resumed = await loadVaultSession(me.email);
                        if (resumed) {
                            setSession({ user: me, keys: resumed });
                            setSettings(await api<Settings>('/api/settings'));
                            setCollections(await api<Collection[]>('/api/collections'));
                        }
                    }
                }
                setOidcReady(true);
            })
            .catch((e) => setFatal(tr(`Не вдалося завантажити конфігурацію: ${e.message}`, `Could not load configuration: ${e.message}`)));
    }, []);

    const refreshCollections = useCallback(async () => {
        setCollections(await api<Collection[]>('/api/collections'));
    }, []);

    const unlock = useCallback(async (passphrase: string, dev?: { email: string; roles: string; groups: string }) => {
        if (dev) {
            setDevIdentity(dev);
        }
        const user = await api<Me>('/api/me');
        const keys = await loadOrCreateKeys(passphrase);
        await saveVaultSession(user.email, keys);
        setSession({ user, keys });
        setVaultSalt(await fetchVaultSalt());
        setSettings(await api<Settings>('/api/settings'));
        await refreshCollections();
    }, [refreshCollections]);

    const create = useCallback(async (passphrase: string) => {
        const user = bootstrapUser ?? await api<Me>('/api/me');
        const keys = await createVault(passphrase);
        // A vault created from scratch still gets a brand-new keypair, so an
        // enrolment surviving from an earlier vault is just as stale as after a
        // reset.
        removeVaultWebAuthn(user.email);
        await saveVaultSession(user.email, keys);
        setSession({ user, keys }); setHasVault(true);
        setVaultSalt(await fetchVaultSalt());
        setSettings(await api<Settings>('/api/settings')); await refreshCollections();
    }, [bootstrapUser, refreshCollections]);

    const recover = useCallback(async (passphrase: string) => {
        const user = bootstrapUser ?? await api<Me>('/api/me');
        const keys = await resetVault(passphrase);
        // The passkey blob wraps the *old* passphrase, so it can only ever hand
        // back a passphrase the new keys reject. Drop the enrolment on reset;
        // the user re-enables it in Settings under the new passphrase.
        removeVaultWebAuthn(user.email);
        clearLocalItems(user.email); await saveVaultSession(user.email, keys);
        setSession({ user, keys }); setHasVault(true);
        setVaultSalt(await fetchVaultSalt());
        setCollections([]); setSettings(await api<Settings>('/api/settings'));
    }, [bootstrapUser]);

    const lock = useCallback(() => {
        // An explicit lock must not be resumable, otherwise the next boot walks
        // straight back into the vault.
        void clearVaultSession();
        setSession(null);
        setCollections([]);
        setTab('vault');
        setVaultItemToOpen(null);
    }, []);

    const logout = useCallback(() => {
        lock();
        if (config?.authMode === 'oidc') {
            oidcLogout();
        }
    }, [config, lock]);

    if (fatal) {
        return <p className="error" style={{ padding: 24 }}>{fatal}</p>;
    }
    if (!config || !oidcReady) {
        return <p className="hint" style={{ padding: 24 }}>{tr('Завантаження…', 'Loading…')}</p>;
    }

    const isAuditor = session != null
        && (session.user.roles.includes('ADMIN') || session.user.roles.includes('SECURITY'));

    return (
        <div className="app-shell">
            <header className="topbar">
                <div className="brand"><span className="brand-mark" aria-hidden="true"><IconLock /></span><span>KSE Password Manager</span></div>
                <div className="header-right">
                    <LanguageSwitcher />
                    {session && (
                        config.authMode === 'oidc' ? (
                            <a id="user-badge" className="topbar-user" href={`${config.keycloakUrl}/realms/${encodeURIComponent(config.realm ?? '')}/account/`}
                               target="_blank" rel="noopener noreferrer" title={tr('Керування профілем і 2FA в Account Console', 'Manage your profile and 2FA in the Account Console')}>
                                {settings.avatarDataUrl
                                    ? <img className="avatar" src={settings.avatarDataUrl} alt="" width={28} height={28} />
                                    : <span className="avatar">{(session.user.displayName || session.user.email).slice(0, 1).toUpperCase()}</span>}
                                <span className="topbar-identity"><strong>{session.user.displayName || session.user.email}</strong><small>{session.user.email}</small></span>
                            </a>
                        ) : (
                            <span id="user-badge" className="topbar-user">
                                {settings.avatarDataUrl
                                    ? <img className="avatar" src={settings.avatarDataUrl} alt="" width={28} height={28} />
                                    : <span className="avatar">{(session.user.displayName || session.user.email).slice(0, 1).toUpperCase()}</span>}
                                <span className="topbar-identity"><strong>{session.user.displayName || session.user.email}</strong><small>{session.user.email}</small></span>
                            </span>
                        )
                    )}
                    {session && <button id="lock-btn" className="secondary icon-btn" onClick={lock} title={t('lock')} aria-label={t('lock')}><IconLock /></button>}
                    {(session || bootstrapUser) && config.authMode === 'oidc'
                        && <button id="logout-btn" className="secondary" onClick={logout}>{t('logout')}</button>}
                </div>
            </header>

            {!session && <UnlockScreen devMode={config.authMode === 'dev-headers'} user={bootstrapUser}
                                      hasVault={hasVault} vaultSalt={vaultSalt} startRecovery={resetRequested}
                                      onUnlock={unlock} onCreate={create} onReset={recover} />}

            {session && <div className="workspace-shell">
                <aside className="sidebar">
                    <p className="sidebar-label">VAULT</p>
                    <button className={`nav-item ${tab === 'vault' ? 'active' : ''}`} aria-current={tab === 'vault' ? 'page' : undefined} onClick={() => setTab('vault')}><IconVault /> <span>{t('vault')}</span></button>
                    <button id="dashboard-tab-btn" className={`nav-item ${tab === 'dashboard' ? 'active' : ''}`} aria-current={tab === 'dashboard' ? 'page' : undefined} onClick={() => setTab('dashboard')}><IconDashboard /> <span>{t('dashboard')}</span></button>
                    <button id="collections-tab-btn" className={`nav-item ${tab === 'collections' ? 'active' : ''}`} aria-current={tab === 'collections' ? 'page' : undefined} onClick={() => setTab('collections')}><IconCollections /> <span>{t('collections')}</span></button>
                    <button id="tags-tab-btn" className={`nav-item ${tab === 'tags' ? 'active' : ''}`} aria-current={tab === 'tags' ? 'page' : undefined} onClick={() => setTab('tags')}><IconTag /> <span>{t('tags')}</span></button>
                    {isAuditor && <><p className="sidebar-label">SECURITY</p><button id="audit-tab-btn" className={`nav-item ${tab === 'audit' ? 'active' : ''}`} aria-current={tab === 'audit' ? 'page' : undefined} onClick={() => setTab('audit')}><IconActivity /> <span>{t('activity')}</span></button></>}
                    {session.user.roles.includes('ADMIN') && <button id="admin-tab-btn" className={`nav-item ${tab === 'admin' ? 'active' : ''}`} aria-current={tab === 'admin' ? 'page' : undefined} onClick={() => setTab('admin')}><IconUsers /> <span>{t('admin')}</span></button>}
                    <div className="sidebar-bottom"><button className={`nav-item ${tab === 'settings' ? 'active' : ''}`} aria-current={tab === 'settings' ? 'page' : undefined} onClick={() => setTab('settings')}><IconSettings /> <span>{t('settings')}</span></button></div>
                </aside>
                <main id="app" className="workspace-main">
                    <div className="page-heading">
                        <div><h1>{tab === 'vault' ? t('vault') : tab === 'dashboard' ? t('dashboard') : tab === 'collections' ? t('collections') : tab === 'tags' ? t('tags') : tab === 'audit' ? t('activity') : tab === 'admin' ? t('admin') : t('settings')}</h1></div>
                    </div>
                    {tab === 'vault' && (
                        <VaultTab session={session} settings={settings} collections={collections} tagFilter={vaultTagFilter} onClearTagFilter={() => setVaultTagFilter(null)}
                                  openItemId={vaultItemToOpen} onItemOpened={() => setVaultItemToOpen(null)} />
                    )}
                    {tab === 'dashboard' && <DashboardTab session={session} collections={collections}
                        onOpenItem={(id) => { setVaultItemToOpen(id); setTab('vault'); }} />}
                    {tab === 'collections' && (
                        <CollectionsTab session={session} collections={collections}
                                        onChanged={refreshCollections} />
                    )}
                    {tab === 'tags' && <TagsTab session={session} onSelect={(tag) => { setVaultTagFilter(tag); setTab('vault'); }} />}
                    {tab === 'audit' && <AuditTab />}
                    {tab === 'admin' && <AdminTab />}
                    {tab === 'settings' && <SettingsTab settings={settings} onSaved={setSettings} isAdmin={session.user.roles.includes('ADMIN')} config={config} user={session.user} vaultSalt={vaultSalt} />}
                </main>
            </div>}
        </div>
    );
}
