import { useEffect, useState } from 'react';
import { api } from '../api';
import { IconWarning } from './Icons';
import type { Anomaly, AuditEvent } from '../types';

export function AuditTab() {
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
                    <strong className="row"><IconWarning /> Виявлено аномальну активність:</strong>
                    <ul style={{ margin: '4px 0 0 20px' }}>
                        {anomalies.map((a, i) => (
                            <li key={i}>
                                {a.actorEmail}: {a.count}× {a.action} за останні {a.windowMinutes} хв
                                {' '}(поріг {a.threshold})
                            </li>
                        ))}
                    </ul>
                </div>
            )}
            <table className="audit-table">
                <thead>
                <tr><th>Час</th><th>Користувач</th><th>Дія</th><th>Запис</th><th>Кому</th><th>Деталі</th></tr>
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
