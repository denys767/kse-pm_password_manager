import { FormEvent, useState } from 'react';

interface Props {
    devMode: boolean;
    onUnlock: (passphrase: string, dev?: { email: string; roles: string; groups: string }) => Promise<void>;
}

export function UnlockScreen({ devMode, onUnlock }: Props) {
    const [email, setEmail] = useState('');
    const [roles, setRoles] = useState('');
    const [groups, setGroups] = useState('');
    const [passphrase, setPassphrase] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    async function submit(event: FormEvent) {
        event.preventDefault();
        setError(null);
        if (!passphrase || (devMode && !email)) {
            setError('Вкажіть email і passphrase.');
            return;
        }
        setBusy(true);
        try {
            await onUnlock(passphrase, devMode ? { email: email.trim().toLowerCase(), roles, groups } : undefined);
        } catch (e) {
            const message = (e as Error).message;
            setError(message.startsWith('Невірний') ? message : `Не вдалося увійти: ${message}`);
        } finally {
            setBusy(false);
        }
    }

    return (
        <section id="unlock-screen" className="card narrow">
            <h2>Unlock vault</h2>
            <p className="hint">
                {devMode
                    ? 'Dev-режим: identity передається X-Dev-* заголовками.'
                    : 'Ви увійшли через корпоративний SSO.'}{' '}
                Passphrase розшифровує ваші записи локально в браузері й ніколи не надсилається на сервер.
            </p>
            <form onSubmit={submit}>
                {devMode && (
                    <>
                        <label>Email (dev mode)
                            <input id="dev-email" type="email" placeholder="you@kse.org.ua"
                                   autoComplete="username"
                                   value={email} onChange={(e) => setEmail(e.target.value)} />
                        </label>
                        <label>Ролі (dev mode, через кому: user, admin, security)
                            <input id="dev-roles" type="text" placeholder="user"
                                   value={roles} onChange={(e) => setRoles(e.target.value)} />
                        </label>
                        <label>Групи (dev mode, через кому)
                            <input id="dev-groups" type="text" placeholder="dev-team"
                                   value={groups} onChange={(e) => setGroups(e.target.value)} />
                        </label>
                    </>
                )}
                <label>Vault passphrase
                    <input id="passphrase" type="password" autoComplete="current-password"
                           value={passphrase} onChange={(e) => setPassphrase(e.target.value)} />
                </label>
                <button id="unlock-btn" type="submit" disabled={busy}>
                    {busy ? 'Unlocking…' : 'Unlock'}
                </button>
                {error && <p id="unlock-error" className="error">{error}</p>}
            </form>
        </section>
    );
}
