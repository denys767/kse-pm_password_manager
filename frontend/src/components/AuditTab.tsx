import { useEffect, useState } from 'react';
import { api } from '../api';
import type { AuditEvent } from '../types';

export function AuditTab() {
    const [events, setEvents] = useState<AuditEvent[]>([]);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        api<AuditEvent[]>('/api/audit?limit=200')
            .then(setEvents)
            .catch((e) => setError((e as Error).message));
    }, []);

    return (
        <section id="tab-audit" className="tab-panel">
            {error && <p className="error">{error}</p>}
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
