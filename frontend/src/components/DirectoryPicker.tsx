import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { useI18n } from '../i18n';
import { IconUser, IconUsers } from './Icons';
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
    const { language } = useI18n();
    const tr = (uk: string, en: string) => (language === 'uk' ? uk : en);
    const [matches, setMatches] = useState<DirectoryPrincipal[]>([]);
    const [hint, setHint] = useState<string | null>(null);
    const [active, setActive] = useState(-1);
    // Ignore stale responses when the user keeps typing (debounced calls can
    // resolve out of order).
    const requestId = useRef(0);

    useEffect(() => {
        const query = value.trim();
        if (query.length < 2) { setMatches([]); setHint(null); setActive(-1); return; }
        const seq = ++requestId.current;
        const timer = window.setTimeout(async () => {
            try {
                const found = await api<DirectoryPrincipal[]>(
                    `/api/directory/principals?query=${encodeURIComponent(query)}&types=${types}`);
                if (seq !== requestId.current) return;
                setMatches(found); setHint(null); setActive(-1);
            } catch {
                if (seq !== requestId.current) return;
                setMatches([]); setActive(-1);
                setHint(tr('Каталог Workspace недоступний — введіть повну адресу вручну.',
                    'The Workspace directory is unavailable — type the full address manually.'));
            }
        }, 200);
        return () => window.clearTimeout(timer);
        // tr depends only on language; recomputing on every value change is fine.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [value, types, language]);

    function choose(principal: DirectoryPrincipal) {
        onSelect(principal);
        setMatches([]); setHint(null); setActive(-1);
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
            setMatches([]); setActive(-1);
        }
    }

    return (
        <div className="directory-picker">
            <input id={id} type="text" autoComplete="off" role="combobox" aria-expanded={matches.length > 0}
                   aria-autocomplete="list" disabled={disabled} value={value} placeholder={placeholder}
                   onChange={(e) => onTextChange(e.target.value)} onKeyDown={onKeyDown} />
            {hint && <p className="hint directory-hint">{hint}</p>}
            {matches.length > 0 && <ul className="permission-list directory-suggestions"
                                      aria-label={tr('Результати каталогу', 'Directory results')}>
                {matches.map((principal, index) => <li key={`${principal.type}:${principal.id}`}>
                    <button type="button" className={`linklike${index === active ? ' active' : ''}`}
                            onMouseEnter={() => setActive(index)}
                            onClick={() => choose(principal)}>
                        {principal.type === 'GROUP' ? <IconUsers /> : <IconUser />} {principal.displayName} — {principal.email}
                    </button>
                </li>)}
            </ul>}
        </div>
    );
}
