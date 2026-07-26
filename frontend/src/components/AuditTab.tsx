import { useEffect, useState } from 'react';
import { api } from '../api';
import { IconWarning } from './Icons';
import { useI18n } from '../i18n';
import type { Anomaly, AuditPage } from '../types';

const PAGE_SIZE = 50;

const ACTIONS = [
    'LOGIN', 'LOGIN_FAILED', 'LOGOUT', 'ITEM_CREATED', 'ITEM_VIEWED', 'ITEM_UPDATED', 'ITEM_DELETED',
    'ITEM_COPIED', 'ITEM_SHARED', 'ACCESS_REVOKED', 'SYNC_MODE_CHANGED', 'COLLECTION_CREATED',
    'COLLECTION_DELETED', 'COLLECTION_MEMBER_ADDED', 'COLLECTION_MEMBER_ROLE_CHANGED',
    'COLLECTION_MEMBER_REMOVED', 'COLLECTION_MEMBER_PENDING', 'COLLECTION_MEMBER_AUTO_REMOVED',
    'COLLECTION_SYNC', 'ITEM_COLLECTION_CHANGED', 'ITEM_KEY_ROTATED', 'PASSKEY_CREATED', 'PASSKEY_USED',
    'COLLECTION_KEY_ROTATED', 'EXTERNAL_SHARE_CREATED', 'EXTERNAL_SHARE_VIEWED', 'EXTERNAL_SHARE_EXPIRED',
    'EXTERNAL_SHARE_REVOKED', 'EXTERNAL_SHARE_EXTENDED', 'ATTACHMENT_UPLOADED', 'ATTACHMENT_DOWNLOADED',
    'ATTACHMENT_DELETED', 'VAULT_RESET', 'OWNERSHIP_TRANSFERRED', 'PERMISSION_ROLE_CHANGED',
    'WORKSPACE_USER_ROLE_CHANGED', 'WORKSPACE_USER_STATUS_CHANGED',
    // Written only before the KMS recovery escrow was removed; kept so historic
    // events stay filterable.
    'RECOVERY_ENVELOPE_UPLOADED', 'RECOVERY_OPERATION_CREATED', 'RECOVERY_OPERATION_COMPLETED',
    'RECOVERY_OPERATION_FAILED', 'WORKSPACE_USER_REVOKED', 'RECOVERY_NOTIFICATION_CREATED',
];

export function AuditTab() {
    const { language } = useI18n();
    const tr = (uk: string, en: string) => (language === 'uk' ? uk : en);
    const [page, setPage] = useState<AuditPage | null>(null);
    const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);

    const [pageIndex, setPageIndex] = useState(0);
    const [actorInput, setActorInput] = useState('');
    const [actorEmail, setActorEmail] = useState('');
    const [action, setAction] = useState('');
    const [from, setFrom] = useState('');
    const [to, setTo] = useState('');

    // Debounce the free-typed actor filter so we don't fire a request per keystroke.
    useEffect(() => {
        const timer = window.setTimeout(() => {
            setActorEmail(actorInput.trim());
            setPageIndex(0);
        }, 300);
        return () => window.clearTimeout(timer);
    }, [actorInput]);

    useEffect(() => {
        api<Anomaly[]>('/api/audit/anomalies').then(setAnomalies).catch((e) => setError((e as Error).message));
    }, []);

    useEffect(() => {
        const params = new URLSearchParams({ page: String(pageIndex), size: String(PAGE_SIZE) });
        if (actorEmail) params.set('actorEmail', actorEmail);
        if (action) params.set('action', action);
        if (from) params.set('from', new Date(from).toISOString());
        if (to) params.set('to', new Date(to).toISOString());

        let cancelled = false;
        setLoading(true);
        api<AuditPage>(`/api/audit?${params.toString()}`)
            .then((result) => { if (!cancelled) { setPage(result); setError(null); } })
            .catch((e) => { if (!cancelled) setError((e as Error).message); })
            .finally(() => { if (!cancelled) setLoading(false); });
        return () => { cancelled = true; };
    }, [pageIndex, actorEmail, action, from, to]);

    function resetFilters() {
        setActorInput(''); setActorEmail(''); setAction(''); setFrom(''); setTo(''); setPageIndex(0);
    }

    const events = page?.content ?? [];
    const totalPages = page?.totalPages ?? 0;

    return (
        <section id="tab-audit" className="tab-panel">
            {error && <p className="error">{error}</p>}
            {anomalies.length > 0 && (
                <div id="anomaly-banner" className="error" style={{ marginBottom: 12 }}>
                    <strong className="row"><IconWarning /> {tr('Виявлено аномальну активність:', 'Anomalous activity detected:')}</strong>
                    <ul style={{ margin: '4px 0 0 20px' }}>
                        {anomalies.map((a, i) => (
                            <li key={i}>
                                {a.actorEmail}: {a.count}× {a.action} {tr(`за останні ${a.windowMinutes} хв`, `in the last ${a.windowMinutes} min`)}
                                {' '}({tr('поріг', 'threshold')} {a.threshold})
                            </li>
                        ))}
                    </ul>
                </div>
            )}
            <div className="toolbar" style={{ marginBottom: 12, flexWrap: 'wrap' }}>
                <input type="text" placeholder={tr('Користувач…', 'Actor email…')} value={actorInput}
                       onChange={(e) => setActorInput(e.target.value)} style={{ minWidth: 200 }} />
                <select value={action} onChange={(e) => { setAction(e.target.value); setPageIndex(0); }}>
                    <option value="">{tr('Усі дії', 'All actions')}</option>
                    {ACTIONS.map((a) => <option key={a} value={a}>{a}</option>)}
                </select>
                <label className="row" style={{ gap: 4 }}>
                    {tr('Від', 'From')}
                    <input type="date" value={from} onChange={(e) => { setFrom(e.target.value); setPageIndex(0); }} />
                </label>
                <label className="row" style={{ gap: 4 }}>
                    {tr('До', 'To')}
                    <input type="date" value={to} onChange={(e) => { setTo(e.target.value); setPageIndex(0); }} />
                </label>
                <button type="button" className="secondary small" onClick={resetFilters}>
                    {tr('Скинути', 'Reset')}
                </button>
            </div>
            {loading && events.length === 0 ? (
                <p>{tr('Завантаження…', 'Loading…')}</p>
            ) : events.length === 0 ? (
                <p className="hint">{tr('Записів не знайдено.', 'No events found.')}</p>
            ) : (
                <table className="audit-table" aria-busy={loading}>
                    <thead>
                    <tr><th>{tr('Час', 'Time')}</th><th>{tr('Користувач', 'User')}</th><th>{tr('Дія', 'Action')}</th><th>{tr('Запис', 'Item')}</th><th>{tr('Кому', 'Target')}</th><th>{tr('Деталі', 'Details')}</th></tr>
                    </thead>
                    <tbody id="audit-body">
                    {events.map((event) => (
                        <tr key={event.id}>
                            <td>{new Date(event.occurredAt).toLocaleString()}</td>
                            <td>{event.actorEmail}</td>
                            <td>{event.action}</td>
                            <td>{event.itemName || ''}</td>
                            <td>{event.target || ''}</td>
                            <td>{event.details || ''}</td>
                        </tr>
                    ))}
                    </tbody>
                </table>
            )}
            {page && page.totalElements > 0 && (
                <div className="row" style={{ marginTop: 12, alignItems: 'center' }}>
                    <button type="button" className="secondary small" disabled={pageIndex === 0}
                            onClick={() => setPageIndex((p) => Math.max(0, p - 1))}>
                        {tr('← Назад', '← Prev')}
                    </button>
                    <span>{tr(
                        `Сторінка ${pageIndex + 1} з ${totalPages} (усього ${page.totalElements})`,
                        `Page ${pageIndex + 1} of ${totalPages} (${page.totalElements} total)`)}</span>
                    <button type="button" className="secondary small" disabled={pageIndex + 1 >= totalPages}
                            onClick={() => setPageIndex((p) => p + 1)}>
                        {tr('Далі →', 'Next →')}
                    </button>
                </div>
            )}
        </section>
    );
}
