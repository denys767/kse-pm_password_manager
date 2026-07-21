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
import type { Collection, FrontendConfig, Me, Settings } from './types';

export interface Session {
    user: Me;
    keys: VaultKeys;
}

type Tab = 'vault' | 'dashboard' | 'collections' | 'audit' | 'settings';

export default function App() {
    const [config, setConfig] = useState<FrontendConfig | null>(null);
    const [oidcReady, setOidcReady] = useState(false);
    const [session, setSession] = useState<Session | null>(null);
    const [collections, setCollections] = useState<Collection[]>([]);
    const [settings, setSettings] = useState<Settings>({
        defaultSyncMode: 'SERVER_SYNCED',
        clipboardClearSeconds: 20,
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
                <div className="brand"><span>KSE Password Manager</span><small>WORKSPACE</small></div>
                <div className="header-right">
                    {session && <span id="user-badge">{session.user.email}</span>}
                    {session && <button id="lock-btn" className="secondary" onClick={lock}>Lock</button>}
                    {session && config.authMode === 'oidc'
                        && <button id="logout-btn" className="secondary" onClick={logout}>Logout</button>}
                </div>
            </header>

            {!session && <UnlockScreen devMode={config.authMode === 'dev-headers'} user={bootstrapUser}
                                      hasVault={hasVault} startRecovery={resetRequested} onUnlock={unlock} onCreate={create} onReset={recover} />}

            {session && <div className="workspace-shell">
                <aside className="sidebar">
                    <p className="sidebar-label">VAULT</p>
                    <button className={`nav-item ${tab === 'vault' ? 'active' : ''}`} onClick={() => setTab('vault')}>⌂ <span>Усі записи</span></button>
                    <button id="dashboard-tab-btn" className={`nav-item ${tab === 'dashboard' ? 'active' : ''}`} onClick={() => setTab('dashboard')}>◈ <span>Dashboard</span></button>
                    <button id="collections-tab-btn" className={`nav-item ${tab === 'collections' ? 'active' : ''}`} onClick={() => setTab('collections')}>▦ <span>Колекції</span></button>
                    {isAuditor && <><p className="sidebar-label">SECURITY</p><button id="audit-tab-btn" className={`nav-item ${tab === 'audit' ? 'active' : ''}`} onClick={() => setTab('audit')}>◷ <span>Активність</span></button></>}
                    <div className="sidebar-bottom"><button className={`nav-item ${tab === 'settings' ? 'active' : ''}`} onClick={() => setTab('settings')}>⚙ <span>Налаштування</span></button></div>
                </aside>
                <main id="app" className="workspace-main">
                    <div className="page-heading"><div><p className="eyebrow">KSE WORKSPACE</p><h1>{tab === 'vault' ? 'Усі записи' : tab === 'dashboard' ? 'Security dashboard' : tab === 'collections' ? 'Колекції' : tab === 'audit' ? 'Активність' : 'Налаштування'}</h1></div></div>
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
                    {tab === 'settings' && <SettingsTab settings={settings} onSaved={setSettings} />}
                </main>
            </div>}
        </div>
    );
}
