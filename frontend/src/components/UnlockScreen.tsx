import { FormEvent, useEffect, useState } from 'react';
import { api } from '../api';
import { assessPassphrase, PassphraseAssessment } from '../passphrase';
import { reauthenticateForVaultReset } from '../auth';
import type { Me } from '../types';

interface Props {
    devMode: boolean;
    user: Me | null;
    hasVault: boolean;
    onUnlock: (passphrase: string, dev?: { email: string; roles: string; groups: string }) => Promise<void>;
    onCreate: (passphrase: string) => Promise<void>;
    onReset: (passphrase: string) => Promise<void>;
}

type Impact = { allowed: boolean; ownedItemsToDelete: number; incomingSharesToRemove: number; membershipsToRemove: number; blockers: { kind: string; id: string; name: string; reason: string }[] };

export function UnlockScreen({ devMode, user, hasVault, onUnlock, onCreate, onReset }: Props) {
    const [email, setEmail] = useState(''); const [roles, setRoles] = useState(''); const [groups, setGroups] = useState('');
    const [passphrase, setPassphrase] = useState(''); const [confirmation, setConfirmation] = useState('');
    const [assessment, setAssessment] = useState<PassphraseAssessment | null>(null);
    const [error, setError] = useState<string | null>(null); const [busy, setBusy] = useState(false);
    const [recovering, setRecovering] = useState(false); const [impact, setImpact] = useState<Impact | null>(null);
    const [successors, setSuccessors] = useState<Record<string, string>>({});

    const creating = !hasVault || recovering;
    useEffect(() => {
        if (!creating || !user || !passphrase) { setAssessment(null); return; }
        let active = true;
        const timer = window.setTimeout(() => assessPassphrase(passphrase, user).then((v) => active && setAssessment(v)), 150);
        return () => { active = false; window.clearTimeout(timer); };
    }, [creating, passphrase, user]);

    async function submit(event: FormEvent) {
        event.preventDefault(); setError(null);
        if (!passphrase || (devMode && !email)) { setError('Вкажіть email і Vault Passphrase.'); return; }
        if (creating) {
            if (passphrase !== confirmation) { setError('Passphrase і підтвердження не збігаються.'); return; }
            if (!assessment || assessment.score < 3) { setError('Оберіть сильнішу Vault Passphrase.'); return; }
        }
        setBusy(true);
        try {
            if (recovering) await onReset(passphrase);
            else if (!hasVault) await onCreate(passphrase);
            else await onUnlock(passphrase, devMode ? { email: email.trim().toLowerCase(), roles, groups } : undefined);
        } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
    }

    async function beginRecovery() {
        setError(null); setRecovering(true);
        try { setImpact(await api<Impact>('/api/vault/reset-impact')); }
        catch (e) { setError(`${(e as Error).message}. Після повторного входу спробуйте ще раз.`); }
    }

    async function transfer(blocker: Impact['blockers'][number]) {
        const successorEmail = successors[blocker.id]?.trim();
        if (!successorEmail) { setError('Вкажіть email нового власника.'); return; }
        setBusy(true); setError(null);
        try {
            await api('/api/vault/ownership-transfers', { method: 'POST', body: JSON.stringify({ kind: blocker.kind, resourceId: blocker.id, successorEmail }) });
            setImpact(await api<Impact>('/api/vault/reset-impact'));
        } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
    }

    return <section id="unlock-screen" className="unlock-layout">
        <div className="unlock-brand"><span className="brand-mark">K</span><div><strong>KSE Password Manager</strong><span>Private team vault</span></div></div>
        <div className="card narrow unlock-card">
            <p className="eyebrow">{creating ? 'ЗАХИЩЕНИЙ VAULT' : 'ПОВЕРНЕННЯ ДО VAULT'}</p>
            <h1>{recovering ? 'Створіть новий Vault' : !hasVault ? 'Створіть Vault Passphrase' : 'Розблокуйте Vault'}</h1>
            {user && <div className="identity-card"><span className="avatar">{user.displayName.slice(0, 1).toUpperCase()}</span><div><strong>{user.displayName}</strong><small>{user.email}</small></div></div>}
            <p className="hint">{creating ? 'Ця фраза шифрує ваш приватний ключ лише у браузері. Ми не можемо її відновити.' : 'Ваша Vault Passphrase ніколи не надсилається на сервер.'}</p>
            <form onSubmit={submit}>
                {devMode && <><label>Email (dev mode)<input id="dev-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></label><label>Ролі<input id="dev-roles" value={roles} onChange={(e) => setRoles(e.target.value)} /></label><label>Групи<input id="dev-groups" value={groups} onChange={(e) => setGroups(e.target.value)} /></label></>}
                <label>Vault Passphrase<input id="passphrase" type="password" autoComplete={creating ? 'new-password' : 'current-password'} value={passphrase} onChange={(e) => setPassphrase(e.target.value)} autoFocus /></label>
                {creating && <><label>Підтвердіть Vault Passphrase<input id="passphrase-confirmation" type="password" autoComplete="new-password" value={confirmation} onChange={(e) => setConfirmation(e.target.value)} /></label>
                    {assessment && <div className={`passphrase-strength s${assessment.score}`}><div className="strength-track"><div className="strength-bar" style={{ width: `${(assessment.score + 1) * 20}%` }} /></div><strong>{assessment.label}</strong><span>{assessment.message}</span></div>}</>}
                <button id="unlock-btn" type="submit" disabled={busy}>{busy ? 'Зачекайте…' : recovering ? 'Скинути та створити Vault' : !hasVault ? 'Створити Vault' : 'Розблокувати Vault'}</button>
                {error && <p id="unlock-error" className="error">{error}</p>}
            </form>
            {hasVault && !recovering && <button className="linklike recovery-link" onClick={beginRecovery}>Забули Vault Passphrase?</button>}
            {recovering && <div className="recovery-box">{impact?.blockers.length ? <><strong>Спершу передайте командні ресурси</strong><p>Новий власник уже має бути користувачем із доступом до запису або членом колекції.</p>{impact.blockers.map((b) => <div className="transfer-row" key={b.id}><span>{b.name} <small>({b.reason})</small></span><input type="email" placeholder="new.owner@kse.org.ua" value={successors[b.id] || ''} onChange={(e) => setSuccessors((s) => ({ ...s, [b.id]: e.target.value }))} /><button type="button" className="secondary small" disabled={busy} onClick={() => transfer(b)}>Передати</button></div>)}<p>Ця дія потребує свіжого SSO-входу.</p><button type="button" className="secondary" onClick={reauthenticateForVaultReset}>Повторно увійти через SSO</button></> : <><strong>Незворотна дія</strong><p>Буде видалено {impact?.ownedItemsToDelete ?? 0} ваших записів і відкликано доступи. Team resources не видаляються.</p><p>Перед підтвердженням повторно увійдіть через SSO — це захищає від випадкового reset.</p><button type="button" className="secondary" onClick={reauthenticateForVaultReset}>Повторно увійти через SSO</button></>}</div>}
        </div>
    </section>;
}
