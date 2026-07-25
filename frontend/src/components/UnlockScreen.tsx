import { FormEvent, useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { assessPassphrase, PassphraseAssessment } from '../passphrase';
import { reauthenticateForVaultReset, WrongPassphraseError } from '../auth';
import { hasVaultWebAuthn, removeVaultWebAuthn, unlockWithVaultWebAuthn } from '../webauthnVault';
import { hasAcceptedTos, recordTosAcceptance, TOS_SECTIONS } from '../termsOfService';
import { hasAcceptedEula, recordEulaAcceptance, EULA_SECTIONS } from '../eula';
import type { Me } from '../types';
import { useI18n } from '../i18n';

interface Props {
    devMode: boolean;
    user: Me | null;
    hasVault: boolean;
    /** KDF salt of the current keypair; identifies which vault a passkey
     *  enrolment belongs to. */
    vaultSalt: string | null;
    startRecovery: boolean;
    onUnlock: (passphrase: string, dev?: { email: string; roles: string; groups: string }) => Promise<void>;
    onCreate: (passphrase: string) => Promise<void>;
    onReset: (passphrase: string) => Promise<void>;
}

type Impact = { allowed: boolean; ownedItemsToDelete: number; incomingSharesToRemove: number; membershipsToRemove: number; blockers: { kind: string; id: string; name: string; reason: string }[] };

export function UnlockScreen({ devMode, user, hasVault, vaultSalt, startRecovery, onUnlock, onCreate, onReset }: Props) {
    const { language, t } = useI18n(); const tr = (uk: string, en: string) => language === 'uk' ? uk : en;
    const [email, setEmail] = useState(''); const [roles, setRoles] = useState(''); const [groups, setGroups] = useState('');
    const [passphrase, setPassphrase] = useState(''); const [confirmation, setConfirmation] = useState('');
    const [assessment, setAssessment] = useState<PassphraseAssessment | null>(null);
    const [error, setError] = useState<string | null>(null); const [busy, setBusy] = useState(false);
    const [recovering, setRecovering] = useState(false); const [impact, setImpact] = useState<Impact | null>(null);
    const [successors, setSuccessors] = useState<Record<string, string>>({});
    const [tosAccepted, setTosAccepted] = useState(false);
    // The Google Workspace photo: the identity card should show the same face as
    // the rest of the app, and the avatar lookup needs no unlocked vault.
    const [avatarDataUrl, setAvatarDataUrl] = useState<string | null>(null);
    const tosDialogRef = useRef<HTMLDialogElement>(null);
    const eulaDialogRef = useRef<HTMLDialogElement>(null);

    const creating = !hasVault || recovering;
    useEffect(() => {
        if (!user) { setAvatarDataUrl(null); return; }
        api<{ avatarDataUrl: string | null }>(`/api/settings/${encodeURIComponent(user.email)}/avatar`)
            .then((r) => setAvatarDataUrl(r.avatarDataUrl))
            .catch(() => setAvatarDataUrl(null));
    }, [user]);
    useEffect(() => {
        if (creating && user) setTosAccepted(hasAcceptedTos(user.email) && hasAcceptedEula(user.email));
    }, [creating, user]);
    // WebAuthn unlock is a per-device convenience enrolled in Settings; only offer
    // it on the plain unlock screen (not while creating/resetting) for this user,
    // and only when the enrolment belongs to the vault that is actually there.
    const webAuthnAvailable = !devMode && hasVault && !recovering && !!user
        && hasVaultWebAuthn(user.email, vaultSalt);
    useEffect(() => {
        if (!creating || !user || !passphrase) { setAssessment(null); return; }
        let active = true;
        const timer = window.setTimeout(() => assessPassphrase(passphrase, user).then((v) => active && setAssessment(v)), 150);
        return () => { active = false; window.clearTimeout(timer); };
    }, [creating, passphrase, user]);

    async function submit(event: FormEvent) {
        event.preventDefault(); setError(null);
        if (devMode && !email) { setError(tr('Вкажіть email і Vault Passphrase.', 'Enter an email and Vault passphrase.')); return; }
        if (!passphrase) { setError(tr('Вкажіть Vault Passphrase.', 'Enter your Vault passphrase.')); return; }
        if (creating) {
            if (passphrase !== confirmation) { setError(tr('Passphrase і підтвердження не збігаються.', 'The passphrase and confirmation do not match.')); return; }
            if (!assessment || assessment.score < 3) { setError(tr('Оберіть сильнішу Vault Passphrase.', 'Choose a stronger Vault passphrase.')); return; }
            if (!tosAccepted) { setError(t('tosRequired')); return; }
        }
        setBusy(true);
        try {
            if (recovering) await onReset(passphrase);
            else if (!hasVault) await onCreate(passphrase);
            else await onUnlock(passphrase, devMode ? { email: email.trim().toLowerCase(), roles, groups } : undefined);
            if (creating && user) { recordTosAcceptance(user.email); recordEulaAcceptance(user.email); }
        } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
    }

    async function unlockWithWebAuthn() {
        if (!user) return;
        setError(null); setBusy(true);
        try {
            const recovered = await unlockWithVaultWebAuthn(user.email);
            await onUnlock(recovered);
        } catch (e) {
            // The blob still decrypts but the passphrase inside no longer opens the
            // vault: it was reset on another device. The enrolment is dead weight —
            // drop it so this screen stops offering an unlock that cannot work.
            if (e instanceof WrongPassphraseError) {
                removeVaultWebAuthn(user.email);
                setError(tr('Vault було скинуто, тому збережене Passkey-розблокування більше не дійсне. Введіть нову Vault Passphrase.',
                    'The vault was reset, so the saved passkey unlock is no longer valid. Enter your new vault passphrase.'));
            } else {
                setError((e as Error).message);
            }
        } finally { setBusy(false); }
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
            {user && <div className="identity-card">{avatarDataUrl
                ? <img className="avatar" src={avatarDataUrl} alt="" width={28} height={28} />
                : <span className="avatar">{user.displayName.slice(0, 1).toUpperCase()}</span>}<div><strong>{user.displayName}</strong><small>{user.email}</small></div></div>}
            <p className="hint">{creating ? tr('Ця фраза шифрує ваш приватний ключ лише у браузері. Ми не можемо її відновити.', 'This passphrase encrypts your private key only in the browser. We cannot recover it.') : tr('Ваша Vault Passphrase ніколи не надсилається на сервер.', 'Your Vault passphrase is never sent to the server.')}</p>
            <form onSubmit={submit}>
                {devMode && <><label>{tr('Email (режим розробки)', 'Email (development mode)')}<input id="dev-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></label><label>{tr('Ролі', 'Roles')}<input id="dev-roles" value={roles} onChange={(e) => setRoles(e.target.value)} /></label><label>{tr('Групи', 'Groups')}<input id="dev-groups" value={groups} onChange={(e) => setGroups(e.target.value)} /></label></>}
                <label>{tr('Vault Passphrase', 'Vault passphrase')}<input id="passphrase" type="password" autoComplete={creating ? 'new-password' : 'current-password'} value={passphrase} onChange={(e) => setPassphrase(e.target.value)} autoFocus /></label>
                {creating && <><label>{tr('Підтвердіть Vault Passphrase', 'Confirm Vault passphrase')}<input id="passphrase-confirmation" type="password" autoComplete="new-password" value={confirmation} onChange={(e) => setConfirmation(e.target.value)} /></label>
                    {assessment && <div className={`passphrase-strength s${assessment.score}`}><div className="strength-track"><div className="strength-bar" style={{ width: `${(assessment.score + 1) * 20}%` }} /></div><strong>{assessment.label}</strong><span>{assessment.message}</span></div>}
                    <label className="checkbox-row tos-row">
                        <input id="tos-checkbox" type="checkbox" checked={tosAccepted} onChange={(e) => setTosAccepted(e.target.checked)} />
                        <span>{t('tosCheckboxLabel')} — <button type="button" className="linklike" onClick={() => tosDialogRef.current?.showModal()}>{t('tosReview')}</button> · <button type="button" className="linklike" onClick={() => eulaDialogRef.current?.showModal()}>{t('eulaReview')}</button></span>
                    </label></>}
                <button id="unlock-btn" type="submit" disabled={busy || (creating && !tosAccepted)}>{busy ? tr('Зачекайте…', 'Please wait…') : recovering ? tr('Скинути та створити Vault', 'Reset and create vault') : !hasVault ? tr('Створити Vault', 'Create vault') : tr('Розблокувати Vault', 'Unlock vault')}</button>
                {error && <p id="unlock-error" className="error">{error}</p>}
            </form>
            {creating && <dialog id="tos-dialog" ref={tosDialogRef}>
                <h3>{t('tosDialogTitle')}</h3>
                <div className="tos-text">
                    {TOS_SECTIONS.map((section) => <div key={section.title}>
                        <h4>{section.title}</h4>
                        {section.paragraphs.map((p, i) => <p key={i}>{p}</p>)}
                    </div>)}
                </div>
                <div className="dialog-actions">
                    <span className="spacer" />
                    <button type="button" className="secondary" onClick={() => tosDialogRef.current?.close()}>{t('tosClose')}</button>
                    <button type="button" onClick={() => { setTosAccepted(true); tosDialogRef.current?.close(); }}>{t('tosAccept')}</button>
                </div>
            </dialog>}
            {creating && <dialog id="eula-dialog" ref={eulaDialogRef}>
                <h3>{t('eulaDialogTitle')}</h3>
                <div className="tos-text">
                    {EULA_SECTIONS.map((section) => <div key={section.title.en}>
                        <h4>{section.title[language]}</h4>
                        {section.paragraphs.map((p, i) => <p key={i}>{p[language]}</p>)}
                    </div>)}
                </div>
                <div className="dialog-actions">
                    <span className="spacer" />
                    <button type="button" className="secondary" onClick={() => eulaDialogRef.current?.close()}>{t('eulaClose')}</button>
                    <button type="button" onClick={() => { setTosAccepted(true); eulaDialogRef.current?.close(); }}>{t('eulaAccept')}</button>
                </div>
            </dialog>}
            {webAuthnAvailable && <><div className="unlock-divider"><span>{tr('або', 'or')}</span></div>
                <button id="webauthn-unlock-btn" type="button" className="secondary" disabled={busy} onClick={unlockWithWebAuthn}>
                    {tr('Розблокувати через Passkey', 'Unlock with a passkey')}</button></>}
            {hasVault && !recovering && <button className="linklike recovery-link" onClick={requestRecovery}>{tr('Забули Vault Passphrase?', 'Forgot your Vault passphrase?')}</button>}
            {recovering && <button id="recovery-back" className="linklike recovery-link" onClick={cancelRecovery}>{tr('← Повернутися назад', '← Go back')}</button>}
            {recovering && <div className="recovery-box">{impact?.blockers.length ? <><strong>{tr('Спершу передайте командні ресурси', 'Transfer team resources first')}</strong><p>{tr('Новий власник уже має бути користувачем із доступом до запису або членом колекції.', 'The new owner must already be a user with access to the item or a member of the collection.')}</p>{impact.blockers.map((b) => <div className="transfer-row" key={b.id}><span>{b.name} <small>({b.reason})</small></span><input type="email" placeholder="new.owner@kse.org.ua" value={successors[b.id] || ''} onChange={(e) => setSuccessors((s) => ({ ...s, [b.id]: e.target.value }))} /><button type="button" className="secondary small" disabled={busy} onClick={() => transfer(b)}>{tr('Передати', 'Transfer')}</button></div>)}</> : <><strong>{tr('Незворотна дія', 'Irreversible action')}</strong><p>{tr(`Буде видалено ${impact?.ownedItemsToDelete ?? 0} ваших записів і відкликано доступи. Team resources не видаляються.`, `${impact?.ownedItemsToDelete ?? 0} of your items will be deleted and their shares revoked. Team resources are not deleted.`)}</p></>}</div>}
        </div>
    </section>;
}
