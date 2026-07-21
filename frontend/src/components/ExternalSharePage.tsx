import { useEffect, useState } from 'react';
import { ApiError, api } from '../api';
import { decryptShareSnapshot, type ExternalShareSnapshot } from '../externalShare';

interface PublicPackage { encryptedPackage: string; packageIv: string; }

export function ExternalSharePage({ shareId }: { shareId: string }) {
    const [snapshot, setSnapshot] = useState<ExternalShareSnapshot | null>(null);
    const [error, setError] = useState<string | null>(null);
    useEffect(() => {
        const fragmentKey = window.location.hash.slice(1);
        window.history.replaceState(null, '', window.location.pathname);
        if (!fragmentKey) { setError('У посиланні немає ключа розшифрування.'); return; }
        api<PublicPackage>(`/api/external-shares/${encodeURIComponent(shareId)}`)
            .then((pkg) => decryptShareSnapshot(fragmentKey, pkg.encryptedPackage, pkg.packageIv))
            .then(setSnapshot)
            .catch((e) => setError(e instanceof ApiError && e.status === 410
                ? 'Це посилання вже використано, відкликано або його строк дії завершився.'
                : `Не вдалося відкрити секрет: ${(e as Error).message}`));
    }, [shareId]);
    if (error) return <main className="external-share"><h1>Посилання недоступне</h1><p className="error">{error}</p></main>;
    if (!snapshot) return <main className="external-share"><p className="hint">Розшифровую пакет…</p></main>;
    const p = snapshot.payload;
    return <main className="external-share"><p className="eyebrow">KSE PASSWORD MANAGER · EXTERNAL SHARE</p><h1>{snapshot.name}</h1>
        {snapshot.url && <p><a href={snapshot.url} target="_blank" rel="noreferrer">{snapshot.url}</a></p>}
        {snapshot.username && <Secret label="Username" value={snapshot.username} />}
        {snapshot.type === 'LOGIN' && <><Secret label="Пароль" value={snapshot.password} /><Secret label="TOTP seed" value={p.totpSeed} /></>}
        {snapshot.type === 'API_CREDENTIALS' && <><Secret label="API key" value={p.apiKey} /><Secret label="API secret" value={p.apiSecret} /></>}
        {snapshot.type === 'SSH_KEY' && <Secret label="Private key" value={p.sshPrivateKey} />}
        {snapshot.type === 'CARD' && <><Secret label="Номер картки" value={p.cardNumber} /><Secret label="Власник" value={p.cardHolder} /><Secret label="Термін дії" value={p.cardExpiry} /><Secret label="CVV" value={p.cardCvv} /></>}
        {snapshot.type === 'SECURE_NOTE' && <Secret label="Додатковий секрет" value={snapshot.password} />}
        {p.notes && <Secret label="Notes" value={p.notes} />}{snapshot.tags && <p className="hint">Теги: {snapshot.tags}</p>}
    </main>;
}
function Secret({ label, value }: { label: string; value: string }) {
    return value ? <section className="external-secret"><strong>{label}</strong><pre>{value}</pre></section> : null;
}
