import { useCallback, useEffect, useState } from 'react';
import { api } from '../api';
import * as pmc from '../crypto';
import { unwrapItemKeyFor } from '../itemKeys';
import { loadLocalItems } from '../localItems';
import { estimateStrength, hibpBreachCounts } from '../passwords';
import type { Session } from '../App';
import type { Collection, PasswordItem } from '../types';
import { useI18n, type Language } from '../i18n';

const OLD_PASSWORD_DAYS = 90;

type Finding = { item: PasswordItem; detail?: string };
type Findings = { weak: Finding[]; reused: Finding[]; old: Finding[]; breached: Finding[] };

interface Props {
    session: Session;
    collections: Collection[];
    onOpenItem: (id: string) => void;
}

const emptyFindings = (): Findings => ({ weak: [], reused: [], old: [], breached: [] });

/** All analysis happens after unlock, against plaintext held only in this tab's memory. */
export function DashboardTab({ session, collections, onOpenItem }: Props) {
    const { language } = useI18n(); const tr = (uk: string, en: string) => language === 'uk' ? uk : en;
    const [findings, setFindings] = useState<Findings>(emptyFindings);
    const [status, setStatus] = useState(tr('Аналізую локально…', 'Analysing locally…'));
    const [error, setError] = useState<string | null>(null);

    const analyse = useCallback(async () => {
        setStatus(tr('Аналізую локально…', 'Analysing locally…'));
        setError(null);
        try {
            const serverItems = await api<PasswordItem[]>('/api/vault/items');
            const items = [...serverItems, ...loadLocalItems(session.user.email)];
            const readable: Array<{ item: PasswordItem; password: string }> = [];
            for (const item of items) {
                try {
                    const key = await unwrapItemKeyFor(item, collections, session.keys);
                    const password = await pmc.decryptField(key, item.encryptedPassword, item.passwordIv);
                    if (password) readable.push({ item, password });
                } catch {
                    // Metadata-only group shares deliberately have no decryptable item key.
                }
            }

            const next = emptyFindings();
            const now = Date.now();
            const passwords = new Map<string, Array<PasswordItem>>();
            for (const { item, password } of readable) {
                if (estimateStrength(password).score <= 1) next.weak.push({ item });
                if (now - new Date(item.updatedAt).getTime() >= OLD_PASSWORD_DAYS * 86_400_000) {
                    next.old.push({ item, detail: formatAge(item.updatedAt, language) });
                }
                passwords.set(password, [...(passwords.get(password) ?? []), item]);
            }
            for (const group of passwords.values()) {
                if (group.length > 1) group.forEach((item) => next.reused.push({ item, detail: tr(`${group.length} записи`, `${group.length} items`) }));
            }

            // Keep the offline findings useful even if the optional public HIBP
            // service is temporarily unavailable.
            setFindings({ ...next });
            setStatus(tr('Перевіряю компрометовані секрети…', 'Checking compromised secrets…'));
            try {
                const breachCounts = await hibpBreachCounts([...passwords.keys()]);
                for (const [password, count] of breachCounts) {
                    if (count > 0) passwords.get(password)!.forEach((item) => next.breached.push({ item,
                        detail: tr(`${count.toLocaleString('uk-UA')} витоків`, `${count.toLocaleString('en-US')} breaches`) }));
                }
            } catch (hibpError) {
                setError(`HIBP: ${(hibpError as Error).message}`);
            }
            setFindings(next);
            setStatus('');
        } catch (e) {
            setError((e as Error).message);
            setStatus('');
        }
        // `language` is a dependency because the finding details ("3 items",
        // "12 days ago") are built here, so a language switch has to rebuild them.
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [collections, session, language]);

    useEffect(() => { analyse(); }, [analyse]);
    const categories: Array<[keyof Findings, string, string]> = [
        ['weak', tr('Слабкі', 'Weak'), tr('Оцінка стійкості нижча за середню', 'Below-average strength score')],
        ['reused', tr('Повторно використані', 'Reused'), tr('Той самий пароль у кількох записах', 'The same password in multiple items')],
        ['old', tr(`Застарілі (${OLD_PASSWORD_DAYS}+ днів)`, `Old (${OLD_PASSWORD_DAYS}+ days)`), tr('Від останнього оновлення минуло багато часу', 'Not updated for a long time')],
        ['breached', tr('Скомпрометовані', 'Compromised'), tr('Знайдено через HIBP k-anonymity', 'Found through HIBP k-anonymity')],
    ];

    return <section id="tab-dashboard" className="tab-panel dashboard">
        <p className="hint">{tr('Перевірка виконується лише у браузері після розблокування. HIBP отримує тільки SHA-1 префікси з 5 символів.', 'The check runs only in the browser after unlocking. HIBP receives only 5-character SHA-1 prefixes.')}</p>
        {status && <p className="hint" role="status">{status}</p>}
        {error && <p className="error">{tr('Не вдалося завершити аналіз:', 'Analysis could not be completed:')} {error}</p>}
        {!status && !error && categories.every(([key]) => findings[key].length === 0) && <p id="dashboard-empty-state" className="hint">{tr('Чудово: у доступних записах не знайдено слабких, повторно використаних, застарілих або скомпрометованих секретів.', 'Great: no weak, reused, old, or compromised secrets were found in accessible items.')}</p>}
        <div className="dashboard-grid">
            {categories.map(([key, title, description]) => <article className="dashboard-card" key={key}>
                <div><h2>{title}</h2><span className="dashboard-count">{findings[key].length}</span></div>
                <p className="hint">{description}</p>
                <ul id={`dashboard-${key}`} className="dashboard-list">
                    {findings[key].map(({ item, detail }) => <li key={item.id}>
                        <button className="secondary" onClick={() => onOpenItem(item.id)}>{item.name}<small>{detail ?? item.username ?? item.url ?? ''}</small></button>
                    </li>)}
                </ul>
            </article>)}
        </div>
    </section>;
}

function formatAge(updatedAt: string, language: Language): string {
    const days = Math.max(Math.floor((Date.now() - new Date(updatedAt).getTime()) / 86_400_000), 0);
    return language === 'uk' ? `${days} днів тому` : `${days} days ago`;
}
