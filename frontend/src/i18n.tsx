import { createContext, ReactNode, useContext, useEffect, useMemo, useState } from 'react';

export type Language = 'uk' | 'en';
type Values = Record<string, string | number>;

const messages = {
    appName: { uk: 'KSE Менеджер паролів', en: 'KSE Password Manager' },
    vault: { uk: 'Усі записи', en: 'All items' }, dashboard: { uk: 'Панель безпеки', en: 'Security dashboard' },
    collections: { uk: 'Колекції', en: 'Collections' }, tags: { uk: 'Теги', en: 'Tags' },
    activity: { uk: 'Активність', en: 'Activity' }, settings: { uk: 'Налаштування', en: 'Settings' },
    logout: { uk: 'Вийти', en: 'Log out' }, lock: { uk: 'Заблокувати vault', en: 'Lock vault' },
    search: { uk: 'Пошук', en: 'Search' },
    exportCsv: { uk: 'Експорт CSV', en: 'Export CSV' }, importCsv: { uk: 'Імпорт CSV', en: 'Import CSV' },
    addSecret: { uk: '+ Додати запис', en: '+ Add item' }, open: { uk: 'Відкрити', en: 'Open' },
    emptyVault: { uk: 'Vault порожній. Додайте перший запис.', en: 'Your vault is empty. Add your first item.' },
    account: { uk: 'Обліковий запис', en: 'Account' }, accountConsole: { uk: 'Відкрити Account Console', en: 'Open Account Console' },
    accountDescription: { uk: 'У Keycloak Account Console можна змінити ваші особисті дані, включно з біометрією', en: 'In Keycloak Account Console you can update your personal details, including biometrics.' },
    name: { uk: 'Назва', en: 'Name' }, username: { uk: 'Ім’я користувача / логін', en: 'Username / login' }, password: { uk: 'Пароль', en: 'Password' },
    notes: { uk: 'Нотатки', en: 'Notes' }, itemType: { uk: 'Тип запису', en: 'Item type' }, collection: { uk: 'Колекція', en: 'Collection' },
    sharedAccess: { uk: 'Спільний доступ', en: 'Shared access' }, externalShare: { uk: 'Зовнішній спільний доступ', en: 'External sharing' },
    cancel: { uk: 'Скасувати', en: 'Cancel' }, save: { uk: 'Зберегти', en: 'Save' }, delete: { uk: 'Видалити', en: 'Delete' },
    copy: { uk: 'Копіювати', en: 'Copy' }, revoke: { uk: 'Відкликати', en: 'Revoke' }, share: { uk: 'Надати доступ', en: 'Share' },
    createLink: { uk: 'Створити посилання', en: 'Create link' }, tagsHelp: { uk: 'Введіть тег і натисніть Enter або кому', en: 'Type a tag and press Enter or comma' },
    appearance: { uk: 'Вигляд', en: 'Appearance' }, theme: { uk: 'Тема', en: 'Theme' }, themeSystem: { uk: 'Як у системі', en: 'System default' }, themeLight: { uk: 'Світла', en: 'Light' }, themeDark: { uk: 'Темна', en: 'Dark' },
    tagsSearch: { uk: 'Пошук тегів…', en: 'Search tags…' }, tagsEmpty: { uk: 'Тегів ще немає.', en: 'No tags yet.' },
    activeTag: { uk: 'Фільтр за тегом:', en: 'Tag filter:' }, clear: { uk: 'Очистити', en: 'Clear' },
    createCollection: { uk: '+ Створити колекцію', en: '+ Create collection' }, collectionName: { uk: 'Назва нової колекції (напр. Infra)', en: 'New collection name (e.g. Infra)' },
    deleteCollection: { uk: 'Видалити колекцію', en: 'Delete collection' },
    members: { uk: 'учасників', en: 'members' }, owner: { uk: 'власник', en: 'owner' },
    add: { uk: 'Додати', en: 'Add' }, syncGroup: { uk: 'Синхронізувати групу', en: 'Sync group' },
    noCollection: { uk: '— без колекції —', en: '— no collection —' },
    showPassword: { uk: 'Показати пароль', en: 'Show password' }, hidePassword: { uk: 'Приховати пароль', en: 'Hide password' }, generatePassword: { uk: 'Згенерувати пароль', en: 'Generate password' },
    addPassword: { uk: 'Додати пароль', en: 'Add password' },
} as const;

type Key = keyof typeof messages;
type Translation = { language: Language; setLanguage: (language: Language) => void; t: (key: Key, values?: Values) => string };
const I18nContext = createContext<Translation | null>(null);
const storageKey = 'kse-pm-language';

export function I18nProvider({ children }: { children: ReactNode }) {
    const [language, setLanguage] = useState<Language>(() => localStorage.getItem(storageKey) === 'en' ? 'en' : 'uk');
    useEffect(() => { localStorage.setItem(storageKey, language); document.documentElement.lang = language; }, [language]);
    const value = useMemo<Translation>(() => ({ language, setLanguage, t: (key, values) => {
        let result: string = messages[key][language];
        for (const [name, replacement] of Object.entries(values ?? {})) result = result.replaceAll(`{${name}}`, String(replacement));
        return result;
    } }), [language]);
    return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n() {
    const value = useContext(I18nContext);
    if (!value) throw new Error('useI18n must be used inside I18nProvider');
    return value;
}

export function LanguageSwitcher() {
    const { language, setLanguage } = useI18n();
    return <div className="language-switcher" aria-label="Language">
        <button type="button" className={language === 'uk' ? 'active' : ''} onClick={() => setLanguage('uk')} aria-pressed={language === 'uk'}>UA</button>
        <button type="button" className={language === 'en' ? 'active' : ''} onClick={() => setLanguage('en')} aria-pressed={language === 'en'}>EN</button>
    </div>;
}
