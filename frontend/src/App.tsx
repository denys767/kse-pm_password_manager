import { useCallback, useEffect, useState } from 'react';
import { api } from './api';
import { consumeVaultResetIntent, createVault, fetchConfig, initOidc, loadOrCreateKeys, oidcLogout, resetVault, setDevIdentity, VaultKeys } from './auth';
import { clearLocalItems } from './localItems';
import { UnlockScreen } from './components/UnlockScreen';
import { VaultTab } from './components/VaultTab';
import { CollectionsTab } from './components/CollectionsTab';
import { AuditTab } from './components/AuditTab';
import { SettingsTab } from './components/SettingsTab';
import { DashboardTab } from './components/DashboardTab';
import { ExternalSharePage } from './components/ExternalSharePage';
import { IconActivity, IconCollections, IconDashboard, IconLock, IconSettings, IconVault } from './components/Icons';
import type { Collection, FrontendConfig, Me, Settings } from './types';

export interface Session {
    user: Me;
    keys: VaultKeys;
}

type Tab = 'vault' | 'dashboard' | 'collections' | 'audit' | 'settings';

export default function App() {
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
    const [fatal, setFatal] = useState<string | null>(null);
    const [bootstrapUser, setBootstrapUser] = useState<Me | null>(null);
    const [hasVault, setHasVault] = useState(true);
    const [resetRequested, setResetRequested] = useState(false);

    useEffect(() => {
        fetchConfig()
            .then(async (cfg) => {
                setConfig(cfg);
                if (cfg.authMode === 'oidc') {
                    await initOidc(cfg);
                    const me = await api<Me>('/api/me');
                    setBootstrapUser(me);
                    setResetRequested(consumeVaultResetIntent());
                    try { await api('/api/keys/me'); setHasVault(true); }
                    catch (e) { if ((e as { status?: number }).status === 404) setHasVault(false); else throw e; }
                }
                setOidcReady(true);
            })
            .catch((e) => setFatal(`Не вдалося завантажити конфігурацію: ${e.message}`));
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
        setSession({ user, keys });
        setSettings(await api<Settings>('/api/settings'));
        await refreshCollections();
    }, [refreshCollections]);

    const create = useCallback(async (passphrase: string) => {
        const user = bootstrapUser ?? await api<Me>('/api/me');
        const keys = await createVault(passphrase);
        setSession({ user, keys }); setHasVault(true);
        setSettings(await api<Settings>('/api/settings')); await refreshCollections();
    }, [bootstrapUser, refreshCollections]);

    const recover = useCallback(async (passphrase: string) => {
        const user = bootstrapUser ?? await api<Me>('/api/me');
        const keys = await resetVault(passphrase);
        clearLocalItems(user.email); setSession({ user, keys }); setHasVault(true);
        setCollections([]); setSettings(await api<Settings>('/api/settings'));
    }, [bootstrapUser]);

    const lock = useCallback(() => {
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
        return <p className="hint" style={{ padding: 24 }}>Завантаження…</p>;
    }

    const isAuditor = session != null
        && (session.user.roles.includes('ADMIN') || session.user.roles.includes('SECURITY'));

    return (
        <div className="app-shell">
            <header className="topbar">
                <div className="brand"><span>KSE Password Manager</span></div>
                <div className="header-right">
                    {session && (
                        config.authMode === 'oidc' ? (
                            <a id="user-badge" className="topbar-user" href={`${config.keycloakUrl}/realms/${encodeURIComponent(config.realm ?? '')}/account/`}
                               target="_blank" rel="noopener noreferrer" title="Керування акаунтом Keycloak (пароль, passkey, сесії)">
                                {settings.avatarDataUrl
                                    ? <img className="avatar" src={settings.avatarDataUrl} alt="" width={28} height={28} />
                                    : <span className="avatar">{session.user.email.slice(0, 1).toUpperCase()}</span>}
                                {session.user.email}
                            </a>
                        ) : (
                            <span id="user-badge" className="topbar-user">
                                {settings.avatarDataUrl
                                    ? <img className="avatar" src={settings.avatarDataUrl} alt="" width={28} height={28} />
                                    : <span className="avatar">{session.user.email.slice(0, 1).toUpperCase()}</span>}
                                {session.user.email}
                            </span>
                        )
                    )}
                    {(session || bootstrapUser) && config.authMode === 'oidc'
                        && <button id="logout-btn" className="secondary" onClick={logout}>Logout</button>}
                </div>
            </header>

            {!session && <UnlockScreen devMode={config.authMode === 'dev-headers'} user={bootstrapUser}
                                      hasVault={hasVault} startRecovery={resetRequested} onUnlock={unlock} onCreate={create} onReset={recover} />}

            {session && <div className="workspace-shell">
                <aside className="sidebar">
                    <p className="sidebar-label">VAULT</p>
                    <button className={`nav-item ${tab === 'vault' ? 'active' : ''}`} onClick={() => setTab('vault')}><IconVault /> <span>Усі записи</span></button>
                    <button id="dashboard-tab-btn" className={`nav-item ${tab === 'dashboard' ? 'active' : ''}`} onClick={() => setTab('dashboard')}><IconDashboard /> <span>Dashboard</span></button>
                    <button id="collections-tab-btn" className={`nav-item ${tab === 'collections' ? 'active' : ''}`} onClick={() => setTab('collections')}><IconCollections /> <span>Колекції</span></button>
                    {isAuditor && <><p className="sidebar-label">SECURITY</p><button id="audit-tab-btn" className={`nav-item ${tab === 'audit' ? 'active' : ''}`} onClick={() => setTab('audit')}><IconActivity /> <span>Активність</span></button></>}
                    <div className="sidebar-bottom"><button className={`nav-item ${tab === 'settings' ? 'active' : ''}`} onClick={() => setTab('settings')}><IconSettings /> <span>Налаштування</span></button></div>
                </aside>
                <main id="app" className="workspace-main">
                    <div className="page-heading">
                        <div><h1>{tab === 'vault' ? 'Усі записи' : tab === 'dashboard' ? 'Security dashboard' : tab === 'collections' ? 'Колекції' : tab === 'audit' ? 'Активність' : 'Налаштування'}</h1></div>
                        {tab === 'vault' && <button id="lock-btn" className="secondary icon-btn" onClick={lock} title="Lock" aria-label="Lock"><IconLock /></button>}
                    </div>
                    {tab === 'vault' && (
                        <VaultTab session={session} settings={settings} collections={collections}
                                  openItemId={vaultItemToOpen} onItemOpened={() => setVaultItemToOpen(null)} />
                    )}
                    {tab === 'dashboard' && <DashboardTab session={session} collections={collections}
                        onOpenItem={(id) => { setVaultItemToOpen(id); setTab('vault'); }} />}
                    {tab === 'collections' && (
                        <CollectionsTab session={session} collections={collections}
                                        onChanged={refreshCollections} />
                    )}
                    {tab === 'audit' && <AuditTab />}
                    {tab === 'settings' && <SettingsTab settings={settings} onSaved={setSettings} isAdmin={session.user.roles.includes('ADMIN')} config={config} />}
                </main>
            </div>}
        </div>
    );
}
