import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { IconEyeOff, IconUser, IconUsers } from './Icons';
import type { DirectoryPrincipal } from '../types';

interface Props {
    id?: string;
    /** Which Workspace principal kinds to suggest. Defaults to both. */
    types?: 'USER' | 'USER,GROUP';
    value: string;
    placeholder?: string;
    disabled?: boolean;
    /** Fired on every keystroke (free typing keeps working without a suggestion). */
    onTextChange: (text: string) => void;
    /** Fired when a suggestion is picked by mouse or keyboard. */
    onSelect: (principal: DirectoryPrincipal) => void;
}

/**
 * Google Workspace directory autocomplete shared by item sharing and collection
 * membership. Suggestions are selectable by mouse click or keyboard (↑/↓ + Enter);
 * a directory outage degrades to a hint, never a blocking error, because a full
 * email address can still be typed and shared directly.
 */
export function DirectoryPicker({ id, types = 'USER,GROUP', value, placeholder, disabled, onTextChange, onSelect }: Props) {
    const { language, t } = useI18n();
    const tr = (uk: string, en: string) => (language === 'uk' ? uk : en);
    const [matches, setMatches] = useState<DirectoryPrincipal[]>([]);
    const [hint, setHint] = useState<string | null>(null);
    const [active, setActive] = useState(-1);
    const [loading, setLoading] = useState(false);
    // Ignore stale responses when the user keeps typing (debounced calls can
    // resolve out of order).
    const requestId = useRef(0);
    const containerRef = useRef<HTMLDivElement>(null);
    // Picking a suggestion sets `value` to its email, which would otherwise
    // re-trigger the search effect and reopen the dropdown. Skip that one run.
    const skipNextSearch = useRef(false);

    /** Collapse the dropdown without touching the typed text. */
    function dismiss() {
        setMatches([]); setHint(null); setActive(-1); setLoading(false);
    }

    useEffect(() => {
        if (skipNextSearch.current) { skipNextSearch.current = false; dismiss(); return; }
        const query = value.trim();
        if (query.length < 2) { dismiss(); return; }
        const seq = ++requestId.current;
        setLoading(true);
        const timer = window.setTimeout(async () => {
            try {
                const found = await api<DirectoryPrincipal[]>(
                    `/api/directory/principals?query=${encodeURIComponent(query)}&types=${types}`);
                if (seq !== requestId.current) return;
                setMatches(found); setHint(null); setActive(-1); setLoading(false);
            } catch {
                if (seq !== requestId.current) return;
                setMatches([]); setActive(-1); setLoading(false);
                setHint(tr('Каталог Workspace недоступний — введіть повну адресу вручну.',
                    'The Workspace directory is unavailable — type the full address manually.'));
            }
        }, 200);
        return () => window.clearTimeout(timer);
        // tr depends only on language; recomputing on every value change is fine.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [value, types, language]);

    // Collapse the dropdown when focus/click moves elsewhere on the page, so a
    // stale suggestion list never lingers over other fields.
    useEffect(() => {
        function onPointerDown(event: PointerEvent) {
            if (!containerRef.current?.contains(event.target as Node)) dismiss();
        }
        document.addEventListener('pointerdown', onPointerDown);
        return () => document.removeEventListener('pointerdown', onPointerDown);
    }, []);

    function choose(principal: DirectoryPrincipal) {
        // Only arm the skip if the value actually changes (otherwise the effect
        // never re-runs and the flag would wrongly swallow a later search).
        skipNextSearch.current = principal.email !== value;
        onSelect(principal);
        dismiss();
    }

    function onKeyDown(event: React.KeyboardEvent<HTMLInputElement>) {
        if (matches.length === 0) return;
        if (event.key === 'ArrowDown') {
            event.preventDefault();
            setActive((index) => (index + 1) % matches.length);
        } else if (event.key === 'ArrowUp') {
            event.preventDefault();
            setActive((index) => (index <= 0 ? matches.length - 1 : index - 1));
        } else if (event.key === 'Enter') {
            // Never let Enter submit the surrounding dialog form while a
            // suggestion is highlighted.
            event.preventDefault();
            choose(matches[active >= 0 ? active : 0]);
        } else if (event.key === 'Escape') {
            dismiss();
        }
    }

    const open = loading || matches.length > 0;
    return (
        <div className="directory-picker" ref={containerRef}>
            <input id={id} type="text" autoComplete="off" role="combobox" aria-expanded={open}
                   aria-autocomplete="list" disabled={disabled} value={value} placeholder={placeholder}
                   onChange={(e) => onTextChange(e.target.value)} onKeyDown={onKeyDown} />
            {hint && <p className="hint directory-hint">{hint}</p>}
            {open && <ul className="permission-list directory-suggestions" aria-busy={loading}
                        aria-label={tr('Результати каталогу', 'Directory results')}>
                {loading && matches.length === 0 && <li className="directory-loading">
                    <span className="spinner" aria-hidden="true" /> {tr('Пошук…', 'Searching…')}
                </li>}
                {matches.map((principal, index) => {
                    const hidden = principal.type === 'GROUP' && !principal.visibleToUsers;
                    return <li key={`${principal.type}:${principal.id}`}>
                        <button type="button" className={`linklike${index === active ? ' active' : ''}`}
                                onMouseEnter={() => setActive(index)}
                                onClick={() => choose(principal)}>
                            {principal.type === 'GROUP' ? <IconUsers /> : <IconUser />} {principal.displayName} — {principal.email}
                            {hidden && <span className="badge hidden-group" title={t('groupHiddenTooltip')}>
                                <IconEyeOff /> {t('groupHiddenBadge')}
                            </span>}
                        </button>
                    </li>;
                })}
            </ul>}
        </div>
    );
}
