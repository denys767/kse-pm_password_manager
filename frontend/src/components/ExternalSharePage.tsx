import { useState } from 'react';
import { ApiError, api } from '../api';
import { decryptShareSnapshot, type ExternalShareSnapshot } from '../externalShare';
import { LanguageSwitcher, useI18n } from '../i18n';

interface PublicPackage { encryptedPackage: string; packageIv: string; }

/**
 * The decryption key lives only in the URL fragment, and a one-time share is
 * consumed by the very first GET. Capture (and strip) the fragment exactly once
 * per shareId at module scope: this survives React 18 StrictMode's double mount
 * (a component-scoped read would lose the key on the second mount, which already
 * ran replaceState). The actual GET is deferred to an explicit click (reveal())
 * so link-preview crawlers in email/chat clients cannot burn a one-time link
 * before the human opens it.
 */
const capturedKeys = new Map<string, string>();
function takeFragmentKey(shareId: string): string {
    if (!capturedKeys.has(shareId)) {
        capturedKeys.set(shareId, window.location.hash.slice(1));
        window.history.replaceState(null, '', window.location.pathname);
    }
    return capturedKeys.get(shareId)!;
}

export function ExternalSharePage({ shareId }: { shareId: string }) {
    const { language } = useI18n();
    const tr = (uk: string, en: string) => language === 'uk' ? uk : en;
    const [fragmentKey] = useState(() => takeFragmentKey(shareId));
    const [snapshot, setSnapshot] = useState<ExternalShareSnapshot | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    async function reveal() {
        if (!fragmentKey) { setError(tr('У посиланні немає ключа розшифрування.', 'The link has no decryption key.')); return; }
        setBusy(true); setError(null);
        try {
            const pkg = await api<PublicPackage>(`/api/external-shares/${encodeURIComponent(shareId)}`);
            setSnapshot(await decryptShareSnapshot(fragmentKey, pkg.encryptedPackage, pkg.packageIv));
        } catch (e) {
            setError(e instanceof ApiError && e.status === 410
                ? tr('Це посилання вже використано, відкликано або його строк дії завершився.', 'This link was used, revoked, or expired.')
                : `${tr('Не вдалося відкрити секрет:', 'Could not open secret:')} ${(e as Error).message}`);
            setBusy(false);
        }
    }

    if (error) return <main className="external-share"><LanguageSwitcher /><h1>{tr('Посилання недоступне', 'Link unavailable')}</h1><p className="error">{error}</p></main>;
    if (!snapshot) return <main className="external-share"><LanguageSwitcher />
        <p className="eyebrow">KSE PASSWORD MANAGER · EXTERNAL SHARE</p>
        <h1>{tr('Захищений секрет', 'Protected secret')}</h1>
        <p className="hint">{tr('Натисніть, щоб відкрити секрет. Якщо посилання одноразове, воно згорить одразу після перегляду.', 'Click to reveal the secret. If the link is one-time, it is consumed immediately after viewing.')}</p>
        <button type="button" id="reveal-secret" onClick={reveal} disabled={busy || !fragmentKey}>{busy ? tr('Відкриваю…', 'Opening…') : tr('Показати секрет', 'Reveal secret')}</button>
        {!fragmentKey && <p className="error">{tr('У посиланні немає ключа розшифрування.', 'The link has no decryption key.')}</p>}
    </main>;
    const p = snapshot.payload;
    return <main className="external-share"><LanguageSwitcher /><p className="eyebrow">KSE PASSWORD MANAGER · EXTERNAL SHARE</p><h1>{snapshot.name}</h1>
        {snapshot.url && <p><a href={snapshot.url} target="_blank" rel="noreferrer">{snapshot.url}</a></p>}
        {snapshot.username && <Secret label={tr('Ім’я користувача', 'Username')} value={snapshot.username} />}
        {snapshot.type === 'LOGIN' && <><Secret label={tr('Пароль', 'Password')} value={snapshot.password} /><Secret label="TOTP seed" value={p.totpSeed} /></>}
        {snapshot.type === 'API_CREDENTIALS' && <><Secret label="API key" value={p.apiKey} /><Secret label="API secret" value={p.apiSecret} /></>}
        {snapshot.type === 'SSH_KEY' && <Secret label="Private key" value={p.sshPrivateKey} />}
        {snapshot.type === 'CARD' && <><Secret label={tr('Номер картки', 'Card number')} value={p.cardNumber} /><Secret label={tr('Власник', 'Cardholder')} value={p.cardHolder} /><Secret label={tr('Термін дії', 'Expiry')} value={p.cardExpiry} /><Secret label="CVV" value={p.cardCvv} /></>}
        {snapshot.type === 'SECURE_NOTE' && <Secret label={tr('Додатковий секрет', 'Additional secret')} value={snapshot.password} />}
        {p.notes && <Secret label={tr('Нотатки', 'Notes')} value={p.notes} />}{snapshot.tags && <p className="hint">{tr('Теги:', 'Tags:')} {snapshot.tags}</p>}
    </main>;
}
function Secret({ label, value }: { label: string; value: string }) {
    return value ? <section className="external-secret"><strong>{label}</strong><pre>{value}</pre></section> : null;
}
