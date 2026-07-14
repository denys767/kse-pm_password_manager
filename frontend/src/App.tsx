import { useCallback, useEffect, useState } from 'react';
import { api } from './api';
import { fetchConfig, initOidc, loadOrCreateKeys, oidcLogout, setDevIdentity, VaultKeys } from './auth';
import { UnlockScreen } from './components/UnlockScreen';
import { VaultTab } from './components/VaultTab';
import { AuditTab } from './components/AuditTab';
import { SettingsTab } from './components/SettingsTab';
import type { FrontendConfig, Me, Settings } from './types';

export interface Session {
    user: Me;
    keys: VaultKeys;
}

type Tab = 'vault' | 'audit' | 'settings';

export default function App() {
    const [config, setConfig] = useState<FrontendConfig | null>(null);
    const [oidcReady, setOidcReady] = useState(false);
    const [session, setSession] = useState<Session | null>(null);
    const [settings, setSettings] = useState<Settings>({
        defaultSyncMode: 'SERVER_SYNCED',
        clipboardClearSeconds: 20,
    });
    const [tab, setTab] = useState<Tab>('vault');
    const [fatal, setFatal] = useState<string | null>(null);

    useEffect(() => {
        fetchConfig()
            .then(async (cfg) => {
                setConfig(cfg);
                if (cfg.authMode === 'oidc') {
                    await initOidc(cfg);
                }
                setOidcReady(true);
            })
            .catch((e) => setFatal(`Не вдалося завантажити конфігурацію: ${e.message}`));
    }, []);

    const unlock = useCallback(async (passphrase: string, dev?: { email: string; roles: string; groups: string }) => {
        if (dev) {
            setDevIdentity(dev);
        }
        const user = await api<Me>('/api/me');
        const keys = await loadOrCreateKeys(passphrase);
        setSession({ user, keys });
        setSettings(await api<Settings>('/api/settings'));
    }, []);

    const lock = useCallback(() => {
        setSession(null);
        setTab('vault');
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
        <>
            <header>
                <div className="brand">🔐 KSE Password Manager</div>
                <div className="header-right">
                    {session && <span id="user-badge">{session.user.email}</span>}
                    {session && <button id="lock-btn" className="secondary" onClick={lock}>Lock</button>}
                    {session && config.authMode === 'oidc'
                        && <button id="logout-btn" className="secondary" onClick={logout}>Logout</button>}
                </div>
            </header>

            {!session && <UnlockScreen devMode={config.authMode === 'dev-headers'} onUnlock={unlock} />}

            {session && (
                <main id="app">
                    <nav className="tabs">
                        <button className={`tab ${tab === 'vault' ? 'active' : ''}`}
                                onClick={() => setTab('vault')}>Vault</button>
                        {isAuditor && (
                            <button id="audit-tab-btn" className={`tab ${tab === 'audit' ? 'active' : ''}`}
                                    onClick={() => setTab('audit')}>Audit log</button>
                        )}
                        <button className={`tab ${tab === 'settings' ? 'active' : ''}`}
                                onClick={() => setTab('settings')}>Settings</button>
                    </nav>
                    {tab === 'vault' && <VaultTab session={session} settings={settings} />}
                    {tab === 'audit' && <AuditTab />}
                    {tab === 'settings' && <SettingsTab settings={settings} onSaved={setSettings} />}
                </main>
            )}
        </>
    );
}
