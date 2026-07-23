import { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import type { AdminRecordMetadata, AdminTagSummary, WorkspaceGroup, WorkspaceUser } from '../types';

/** Defensive Workspace governance UI: all data is server metadata, never vault ciphertext. */
export function AdminTab() {
    const [users, setUsers] = useState<WorkspaceUser[]>([]);
    const [groups, setGroups] = useState<WorkspaceGroup[]>([]);
    const [records, setRecords] = useState<AdminRecordMetadata[]>([]);
    const [tags, setTags] = useState<AdminTagSummary[]>([]);
    const [query, setQuery] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);

    const load = useCallback(async () => {
        try {
            const [nextUsers, nextGroups, nextRecords, nextTags] = await Promise.all([
                api<WorkspaceUser[]>(`/api/admin/workspace/users?query=${encodeURIComponent(query)}`),
                api<WorkspaceGroup[]>('/api/admin/workspace/groups'),
                api<AdminRecordMetadata[]>('/api/admin/workspace/records'),
                api<AdminTagSummary[]>('/api/admin/tags'),
            ]);
            setUsers(nextUsers); setGroups(nextGroups); setRecords(nextRecords); setTags(nextTags); setError(null);
        } catch (e) { setError((e as Error).message); }
    }, [query]);
    useEffect(() => { void load(); }, [load]);

    async function refreshDirectory() {
        setBusy(true);
        try { await api('/api/admin/workspace/refresh', { method: 'POST' }); await load(); }
        catch (e) { setError((e as Error).message); } finally { setBusy(false); }
    }
    async function updateUser(user: WorkspaceUser, change: Record<string, unknown>) {
        try {
            const saved = await api<WorkspaceUser>(`/api/admin/workspace/users/${encodeURIComponent(user.email)}`, {
                method: 'PATCH', body: JSON.stringify(change),
            });
            setUsers((all) => all.map((candidate) => candidate.email === saved.email ? saved : candidate));
        } catch (e) { setError((e as Error).message); }
    }
    async function updateGroup(group: WorkspaceGroup, visibleToUsers: boolean) {
        try {
            const saved = await api<WorkspaceGroup>(`/api/admin/workspace/groups/${encodeURIComponent(group.email)}`, {
                method: 'PATCH', body: JSON.stringify({ visibleToUsers }),
            });
            setGroups((all) => all.map((candidate) => candidate.email === saved.email ? saved : candidate));
        } catch (e) { setError((e as Error).message); }
    }
    async function renameTag(tag: AdminTagSummary) {
        const newName = window.prompt(`Нова назва для тегу «${tag.name}»`, tag.name)?.trim();
        if (!newName || newName === tag.name) return;
        try {
            const saved = await api<AdminTagSummary>(`/api/admin/tags/${encodeURIComponent(tag.name)}`, {
                method: 'PATCH', body: JSON.stringify({ newName }),
            });
            setTags((all) => all.filter((candidate) => candidate.name.toLowerCase() !== tag.name.toLowerCase())
                .concat(saved).sort((a, b) => a.name.localeCompare(b.name)));
        } catch (e) { setError((e as Error).message); }
    }
    async function deleteTag(tag: AdminTagSummary) {
        if (!window.confirm(`Видалити тег «${tag.name}» з ${tag.usageCount} записів?`)) return;
        try {
            await api<void>(`/api/admin/tags/${encodeURIComponent(tag.name)}`, { method: 'DELETE' });
            setTags((all) => all.filter((candidate) => candidate.name.toLowerCase() !== tag.name.toLowerCase()));
        } catch (e) { setError((e as Error).message); }
    }

    return <section id="tab-admin" className="tab-panel">
        <div className="toolbar"><input type="search" value={query} placeholder="Пошук Workspace користувачів"
            onChange={(e) => setQuery(e.target.value)} /><button type="button" className="secondary" disabled={busy}
            onClick={refreshDirectory}>{busy ? 'Оновлення…' : 'Оновити Google Workspace'}</button></div>
        <p className="hint">Google Workspace є джерелом користувачів і груп. Local override або REVOKED має пріоритет. Дані записів нижче — лише метадані, без ciphertext/ключів/вкладень.</p>
        {error && <p className="error">{error}</p>}
        <h3>Користувачі Workspace</h3>
        <table className="audit-table"><thead><tr><th>Користувач</th><th>Google admin</th><th>App роль</th><th>Статус</th></tr></thead><tbody>
            {users.map((user) => <tr key={user.email}><td>{user.displayName}<br /><small>{user.email}</small></td><td>{user.googleAdmin ? 'так' : 'ні'}</td>
                <td><select value={user.roleOverride ?? ''} onChange={(e) => e.target.value && void updateUser(user, { roleOverride: e.target.value })}>
                    <option value="">Google default</option><option value="ADMIN">ADMIN</option><option value="USER">USER</option></select></td>
                <td><select value={user.status} onChange={(e) => void updateUser(user, { status: e.target.value })}>
                    <option value="ACTIVE">ACTIVE</option><option value="SUSPENDED">SUSPENDED</option><option value="REVOKED">REVOKED</option></select></td></tr>)}
        </tbody></table>
        <h3>Видимість груп</h3>
        <p className="hint">Нові групи за замовчуванням доступні лише адміністраторам, доки їх явно не оприлюднено.</p>
        <table className="audit-table"><thead><tr><th>Група</th><th>Workspace ID</th><th>Видима користувачам</th></tr></thead><tbody>
            {groups.map((group) => <tr key={group.email}><td>{group.displayName}<br /><small>{group.email}</small></td><td><small>{group.directoryId}</small></td>
                <td><input type="checkbox" checked={group.visibleToUsers} onChange={(e) => void updateGroup(group, e.target.checked)} /></td></tr>)}
        </tbody></table>
        <h3>Теги Workspace</h3>
        <p className="hint">Ці зміни застосовуються атомарно лише до server-synced metadata; local-only записи не зачіпаються.</p>
        <table className="audit-table"><thead><tr><th>Тег</th><th>Записів</th><th>Дії</th></tr></thead><tbody>
            {tags.map((tag) => <tr key={tag.name.toLowerCase()}><td>{tag.name}</td><td>{tag.usageCount}</td><td>
                <button type="button" className="secondary small" onClick={() => void renameTag(tag)}>Перейменувати</button>{' '}
                <button type="button" className="secondary small" onClick={() => void deleteTag(tag)}>Видалити</button>
            </td></tr>)}
        </tbody></table>
        <h3>Метадані записів</h3>
        <table className="audit-table"><thead><tr><th>Назва</th><th>Власник</th><th>Шаблон</th><th>Оновлено</th></tr></thead><tbody>
            {records.map((record) => <tr key={record.id}><td>{record.name}</td><td>{record.ownerEmail}</td><td>{record.type}</td><td>{new Date(record.updatedAt).toLocaleString()}</td></tr>)}
        </tbody></table>
    </section>;
}
