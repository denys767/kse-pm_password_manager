import { useEffect, useState } from 'react';
import { api } from '../api';
import { IconWarning } from './Icons';
import { useI18n } from '../i18n';
import type { Anomaly, AuditEvent } from '../types';

export function AuditTab() {
    const { language } = useI18n();
    const tr = (uk: string, en: string) => (language === 'uk' ? uk : en);
    const [events, setEvents] = useState<AuditEvent[]>([]);
    const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        Promise.all([
            api<AuditEvent[]>('/api/audit?limit=200'),
            api<Anomaly[]>('/api/audit/anomalies'),
        ])
            .then(([auditEvents, detected]) => {
                setEvents(auditEvents);
                setAnomalies(detected);
            })
            .catch((e) => setError((e as Error).message));
    }, []);

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
            <table className="audit-table">
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
        </section>
    );
}
