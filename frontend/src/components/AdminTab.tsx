import { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import { useI18n } from '../i18n';
import type { AdminRecordMetadata, AdminTagSummary, DirectoryStatus, WorkspaceGroup, WorkspaceUser } from '../types';

/** Defensive Workspace governance UI: all data is server metadata, never vault ciphertext. */
export function AdminTab() {
    const { language } = useI18n();
    const tr = (uk: string, en: string) => (language === 'uk' ? uk : en);
    const [users, setUsers] = useState<WorkspaceUser[]>([]);
    const [groups, setGroups] = useState<WorkspaceGroup[]>([]);
    const [records, setRecords] = useState<AdminRecordMetadata[]>([]);
    const [tags, setTags] = useState<AdminTagSummary[]>([]);
    const [query, setQuery] = useState('');
    const [error, setError] = useState<string | null>(null);
    const [busy, setBusy] = useState(false);
    const [directory, setDirectory] = useState<DirectoryStatus | null>(null);

    const load = useCallback(async () => {
        try {
            const [nextUsers, nextGroups, nextRecords, nextTags, nextDirectory] = await Promise.all([
                api<WorkspaceUser[]>(`/api/admin/workspace/users?query=${encodeURIComponent(query)}`),
                api<WorkspaceGroup[]>('/api/admin/workspace/groups'),
                api<AdminRecordMetadata[]>('/api/admin/workspace/records'),
                api<AdminTagSummary[]>('/api/admin/tags'),
                api<DirectoryStatus>('/api/admin/workspace/directory-status'),
            ]);
            setUsers(nextUsers); setGroups(nextGroups); setRecords(nextRecords); setTags(nextTags);
            setDirectory(nextDirectory); setError(null);
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
        const newName = window.prompt(tr(`Нова назва для тегу «${tag.name}»`, `New name for the tag “${tag.name}”`), tag.name)?.trim();
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
        if (!window.confirm(tr(`Видалити тег «${tag.name}» з ${tag.usageCount} записів?`, `Delete the tag “${tag.name}” from ${tag.usageCount} items?`))) return;
        try {
            await api<void>(`/api/admin/tags/${encodeURIComponent(tag.name)}`, { method: 'DELETE' });
            setTags((all) => all.filter((candidate) => candidate.name.toLowerCase() !== tag.name.toLowerCase()));
        } catch (e) { setError((e as Error).message); }
    }

    return <section id="tab-admin" className="tab-panel">
        <div className="toolbar"><input type="search" value={query} placeholder={tr('Пошук Workspace користувачів', 'Search Workspace users')}
            onChange={(e) => setQuery(e.target.value)} /><button type="button" className="secondary" disabled={busy}
            onClick={refreshDirectory}>{busy ? tr('Оновлення…', 'Refreshing…') : tr('Оновити Google Workspace', 'Refresh Google Workspace')}</button></div>
        <p className="hint">{tr('Google Workspace є джерелом користувачів і груп. Local override або REVOKED має пріоритет. Дані записів нижче — лише метадані, без ciphertext/ключів/вкладень.', 'Google Workspace is the source of users and groups. A local override or REVOKED takes priority. The item data below is metadata only — no ciphertext, keys, or attachments.')}</p>
        {error && <p className="error">{error}</p>}
        {directory && (directory.lastError || !directory.lastSuccessAt) && <p className="error">
            {directory.lastSuccessAt
                ? tr(`Синхронізація Google Workspace не вдалася (${directory.consecutiveFailures} поспіль). Дані від ${new Date(directory.lastSuccessAt).toLocaleString()}: ${directory.lastError}`,
                     `Google Workspace sync is failing (${directory.consecutiveFailures} in a row). Data is from ${new Date(directory.lastSuccessAt).toLocaleString()}: ${directory.lastError}`)
                : tr(`Google Workspace ще жодного разу не синхронізувався${directory.lastError ? `: ${directory.lastError}` : ''}. Доки снапшот порожній, ролі та відкликання не діють.`,
                     `Google Workspace has never synchronized${directory.lastError ? `: ${directory.lastError}` : ''}. While the snapshot is empty, roles and revocations are not enforced.`)}
        </p>}
        {directory && !directory.credentialUnattended && <p className="error">
            {tr(`Облікові дані Google не працюють без участі людини: ${directory.credentialDetail}. Налаштуйте федерацію ідентичності навантаження (WORKSPACE_FEDERATION_*), запустіть сервіс під прикріпленим service account, або, як останній варіант, змонтуйте ключ сервісного акаунта (GOOGLE_WORKSPACE_CREDENTIALS_PATH).`,
                `Google credentials cannot work unattended: ${directory.credentialDetail}. Configure workload identity federation (WORKSPACE_FEDERATION_* settings), run the service under an attached service account, or — as a last resort — mount a service-account key (GOOGLE_WORKSPACE_CREDENTIALS_PATH).`)}
        </p>}
        {directory?.servingFromSnapshotSince && <p className="hint">
            {tr(`Google Directory недоступний з ${new Date(directory.servingFromSnapshotSince).toLocaleString()}; підказки та перевірка отримувачів відповідають із локального снапшоту.`,
                `Google Directory has been unreachable since ${new Date(directory.servingFromSnapshotSince).toLocaleString()}; suggestions and recipient validation are answered from the local snapshot.`)}
        </p>}
        {directory?.lastSuccessAt && !directory.lastError && <p className="hint">
            {tr(`Останній успішний синк: ${new Date(directory.lastSuccessAt).toLocaleString()} · користувачів: ${directory.knownUsers}`,
                `Last successful sync: ${new Date(directory.lastSuccessAt).toLocaleString()} · users: ${directory.knownUsers}`)}
        </p>}
        <h3>{tr('Користувачі Workspace', 'Workspace users')}</h3>
        <table className="audit-table"><thead><tr><th>{tr('Користувач', 'User')}</th><th>Google admin</th><th>{tr('App роль', 'App role')}</th><th>{tr('Статус', 'Status')}</th></tr></thead><tbody>
            {users.map((user) => <tr key={user.email}><td>{user.displayName}<br /><small>{user.email}</small></td><td>{user.googleAdmin ? tr('так', 'yes') : tr('ні', 'no')}</td>
                <td><select value={user.roleOverride ?? ''} onChange={(e) => e.target.value && void updateUser(user, { roleOverride: e.target.value })}>
                    <option value="">Google default</option><option value="ADMIN">ADMIN</option><option value="USER">USER</option></select></td>
                <td><select value={user.status} onChange={(e) => void updateUser(user, { status: e.target.value })}>
                    <option value="ACTIVE">ACTIVE</option><option value="SUSPENDED">SUSPENDED</option><option value="REVOKED">REVOKED</option></select></td></tr>)}
        </tbody></table>
        <h3>{tr('Видимість груп', 'Group visibility')}</h3>
        <p className="hint">{tr('Нові синхронізовані групи за замовчуванням видимі всім користувачам; зніміть позначку, щоб приховати конкретну групу.', 'New synced groups are visible to all users by default; uncheck a group to hide it.')}</p>
        <table className="audit-table"><thead><tr><th>{tr('Група', 'Group')}</th><th>Workspace ID</th><th>{tr('Видима користувачам', 'Visible to users')}</th></tr></thead><tbody>
            {groups.map((group) => <tr key={group.email}><td>{group.displayName}<br /><small>{group.email}</small></td><td><small>{group.directoryId}</small></td>
                <td><input type="checkbox" checked={group.visibleToUsers} onChange={(e) => void updateGroup(group, e.target.checked)} /></td></tr>)}
        </tbody></table>
        <h3>{tr('Теги Workspace', 'Workspace tags')}</h3>
        <p className="hint">{tr('Ці зміни застосовуються атомарно лише до server-synced metadata; local-only записи не зачіпаються.', 'These changes apply atomically to server-synced metadata only; local-only items are not affected.')}</p>
        <table className="audit-table"><thead><tr><th>{tr('Тег', 'Tag')}</th><th>{tr('Записів', 'Items')}</th><th>{tr('Дії', 'Actions')}</th></tr></thead><tbody>
            {tags.map((tag) => <tr key={tag.name.toLowerCase()}><td>{tag.name}</td><td>{tag.usageCount}</td><td>
                <button type="button" className="secondary small" onClick={() => void renameTag(tag)}>{tr('Перейменувати', 'Rename')}</button>{' '}
                <button type="button" className="secondary small" onClick={() => void deleteTag(tag)}>{tr('Видалити', 'Delete')}</button>
            </td></tr>)}
        </tbody></table>
        <h3>{tr('Метадані записів', 'Item metadata')}</h3>
        <table className="audit-table"><thead><tr><th>{tr('Назва', 'Name')}</th><th>{tr('Власник', 'Owner')}</th><th>{tr('Шаблон', 'Template')}</th><th>{tr('Оновлено', 'Updated')}</th></tr></thead><tbody>
            {records.map((record) => <tr key={record.id}><td>{record.name}</td><td>{record.ownerEmail}</td><td>{record.type}</td><td>{new Date(record.updatedAt).toLocaleString()}</td></tr>)}
        </tbody></table>
    </section>;
}
