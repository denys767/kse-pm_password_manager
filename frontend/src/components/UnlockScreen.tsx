import { FormEvent, useEffect, useState } from 'react';
import { api } from '../api';
import { assessPassphrase, PassphraseAssessment } from '../passphrase';
import { reauthenticateForVaultReset } from '../auth';
import type { Me } from '../types';
import { useI18n } from '../i18n';

interface Props {
    devMode: boolean;
    user: Me | null;
    hasVault: boolean;
    startRecovery: boolean;
    onUnlock: (passphrase: string, dev?: { email: string; roles: string; groups: string }) => Promise<void>;
    onCreate: (passphrase: string) => Promise<void>;
    onReset: (passphrase: string) => Promise<void>;
}

type Impact = { allowed: boolean; ownedItemsToDelete: number; incomingSharesToRemove: number; membershipsToRemove: number; blockers: { kind: string; id: string; name: string; reason: string }[] };

export function UnlockScreen({ devMode, user, hasVault, startRecovery, onUnlock, onCreate, onReset }: Props) {
    const { language } = useI18n(); const tr = (uk: string, en: string) => language === 'uk' ? uk : en;
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
        if (!passphrase || (devMode && !email)) { setError(tr('Вкажіть email і Vault Passphrase.', 'Enter an email and Vault passphrase.')); return; }
        if (creating) {
            if (passphrase !== confirmation) { setError(tr('Passphrase і підтвердження не збігаються.', 'The passphrase and confirmation do not match.')); return; }
            if (!assessment || assessment.score < 3) { setError(tr('Оберіть сильнішу Vault Passphrase.', 'Choose a stronger Vault passphrase.')); return; }
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
        catch (e) { setError(`${(e as Error).message}. ${tr('Після повторного входу спробуйте ще раз.', 'Sign in again and retry.')}`); }
    }

    useEffect(() => {
        if (startRecovery && hasVault && !devMode) beginRecovery();
        // The intent is consumed by App; this component only starts the recovery screen once.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [startRecovery]);

    function requestRecovery() {
        if (devMode) {
            void beginRecovery();
        } else {
            reauthenticateForVaultReset();
        }
    }

    /** Leaves the reset screen and returns to the normal unlock screen without
     * touching any encrypted material. */
    function cancelRecovery() {
        setRecovering(false); setImpact(null); setError(null);
        setPassphrase(''); setConfirmation(''); setSuccessors({});
    }

    async function transfer(blocker: Impact['blockers'][number]) {
        const successorEmail = successors[blocker.id]?.trim();
        if (!successorEmail) { setError(tr('Вкажіть email нового власника.', 'Enter the new owner’s email.')); return; }
        setBusy(true); setError(null);
        try {
            await api('/api/vault/ownership-transfers', { method: 'POST', body: JSON.stringify({ kind: blocker.kind, resourceId: blocker.id, successorEmail }) });
            setImpact(await api<Impact>('/api/vault/reset-impact'));
        } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
    }

    return <section id="unlock-screen" className="unlock-layout">
        <div className="card narrow unlock-card">
            {creating && <p className="eyebrow">{tr('ЗАХИЩЕНИЙ VAULT', 'SECURE VAULT')}</p>}
            <h1>{recovering ? tr('Створіть новий Vault', 'Create a new vault') : !hasVault ? tr('Створіть Vault Passphrase', 'Create a Vault passphrase') : tr('Розблокуйте Vault', 'Unlock vault')}</h1>
            {user && <div className="identity-card"><span className="avatar">{user.displayName.slice(0, 1).toUpperCase()}</span><div><strong>{user.displayName}</strong><small>{user.email}</small></div></div>}
            <p className="hint">{creating ? tr('Ця фраза шифрує ваш приватний ключ лише у браузері. Ми не можемо її відновити.', 'This passphrase encrypts your private key only in the browser. We cannot recover it.') : tr('Ваша Vault Passphrase ніколи не надсилається на сервер.', 'Your Vault passphrase is never sent to the server.')}</p>
            <form onSubmit={submit}>
                {devMode && <><label>{tr('Email (режим розробки)', 'Email (development mode)')}<input id="dev-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></label><label>{tr('Ролі', 'Roles')}<input id="dev-roles" value={roles} onChange={(e) => setRoles(e.target.value)} /></label><label>{tr('Групи', 'Groups')}<input id="dev-groups" value={groups} onChange={(e) => setGroups(e.target.value)} /></label></>}
                <label>{tr('Vault Passphrase', 'Vault passphrase')}<input id="passphrase" type="password" autoComplete={creating ? 'new-password' : 'current-password'} value={passphrase} onChange={(e) => setPassphrase(e.target.value)} autoFocus /></label>
                {creating && <><label>{tr('Підтвердіть Vault Passphrase', 'Confirm Vault passphrase')}<input id="passphrase-confirmation" type="password" autoComplete="new-password" value={confirmation} onChange={(e) => setConfirmation(e.target.value)} /></label>
                    {assessment && <div className={`passphrase-strength s${assessment.score}`}><div className="strength-track"><div className="strength-bar" style={{ width: `${(assessment.score + 1) * 20}%` }} /></div><strong>{assessment.label}</strong><span>{assessment.message}</span></div>}</>}
                <button id="unlock-btn" type="submit" disabled={busy}>{busy ? tr('Зачекайте…', 'Please wait…') : recovering ? tr('Скинути та створити Vault', 'Reset and create vault') : !hasVault ? tr('Створити Vault', 'Create vault') : tr('Розблокувати Vault', 'Unlock vault')}</button>
                {error && <p id="unlock-error" className="error">{error}</p>}
            </form>
            {hasVault && !recovering && <button className="linklike recovery-link" onClick={requestRecovery}>{tr('Забули Vault Passphrase?', 'Forgot your Vault passphrase?')}</button>}
            {recovering && <button id="recovery-back" className="linklike recovery-link" onClick={cancelRecovery}>{tr('← Повернутися назад', '← Go back')}</button>}
            {recovering && <div className="recovery-box">{impact?.blockers.length ? <><strong>{tr('Спершу передайте командні ресурси', 'Transfer team resources first')}</strong><p>{tr('Новий власник уже має бути користувачем із доступом до запису або членом колекції.', 'The new owner must already be a user with access to the item or a member of the collection.')}</p>{impact.blockers.map((b) => <div className="transfer-row" key={b.id}><span>{b.name} <small>({b.reason})</small></span><input type="email" placeholder="new.owner@kse.org.ua" value={successors[b.id] || ''} onChange={(e) => setSuccessors((s) => ({ ...s, [b.id]: e.target.value }))} /><button type="button" className="secondary small" disabled={busy} onClick={() => transfer(b)}>{tr('Передати', 'Transfer')}</button></div>)}</> : <><strong>{tr('Незворотна дія', 'Irreversible action')}</strong><p>{tr(`Буде видалено ${impact?.ownedItemsToDelete ?? 0} ваших записів і відкликано доступи. Team resources не видаляються.`, `${impact?.ownedItemsToDelete ?? 0} of your items will be deleted and their shares revoked. Team resources are not deleted.`)}</p></>}</div>}
        </div>
    </section>;
}
