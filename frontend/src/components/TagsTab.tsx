import { useEffect, useMemo, useState } from 'react';
import { api } from '../api';
import { loadLocalItems } from '../localItems';
import { collectTags } from '../tags';
import { useI18n } from '../i18n';
import type { Session } from '../App';
import type { PasswordItem } from '../types';

export function TagsTab({ session, onSelect }: { session: Session; onSelect: (tag: string) => void }) {
    const { t } = useI18n(); const [items, setItems] = useState<PasswordItem[]>([]); const [query, setQuery] = useState(''); const [error, setError] = useState<string | null>(null);
    useEffect(() => { api<PasswordItem[]>('/api/vault/items').then((server) => setItems([...server, ...loadLocalItems(session.user.email)])).catch((e) => setError(e.message)); }, [session.user.email]);
    const tags = useMemo(() => collectTags(items.map((item) => item.tags)).filter((tag) => tag.name.toLocaleLowerCase().includes(query.trim().toLocaleLowerCase())), [items, query]);
    return <section id="tab-tags" className="tab-panel tags-tab">
        <input type="search" value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t('tagsSearch')} aria-label={t('tagsSearch')} />
        {error && <p className="error">{error}</p>}
        {!error && tags.length === 0 && <p className="hint">{t('tagsEmpty')}</p>}
        <div className="tag-catalog">{tags.map((tag) => <button key={tag.name.toLocaleLowerCase()} type="button" className="tag-catalog-item" onClick={() => onSelect(tag.name)}><span>{tag.name}</span><span>{tag.count}</span></button>)}</div>
    </section>;
}
