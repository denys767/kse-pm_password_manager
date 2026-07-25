import { createContext, ReactNode, useContext, useEffect, useMemo, useState } from 'react';

export type Language = 'uk' | 'en';
type Values = Record<string, string | number>;

const messages = {
    appName: { uk: 'KSE Менеджер паролів', en: 'KSE Password Manager' },
    vault: { uk: 'Усі записи', en: 'All items' }, dashboard: { uk: 'Панель безпеки', en: 'Security dashboard' },
    collections: { uk: 'Колекції', en: 'Collections' }, tags: { uk: 'Теги', en: 'Tags' },
    activity: { uk: 'Активність', en: 'Activity' }, settings: { uk: 'Налаштування', en: 'Settings' },
    admin: { uk: 'Адміністрування', en: 'Administration' },
    logout: { uk: 'Вийти', en: 'Log out' }, lock: { uk: 'Заблокувати vault', en: 'Lock vault' },
    search: { uk: 'Пошук', en: 'Search' },
    exportCsv: { uk: 'Експорт CSV', en: 'Export CSV' }, importCsv: { uk: 'Імпорт CSV', en: 'Import CSV' },
    addSecret: { uk: '+ Додати запис', en: '+ Add item' }, open: { uk: 'Відкрити', en: 'Open' },
    emptyVault: { uk: 'Vault порожній. Додайте перший запис.', en: 'Your vault is empty. Add your first item.' },
    account: { uk: 'Обліковий запис', en: 'Account' }, accountConsole: { uk: 'Відкрити Account Console', en: 'Open Account Console' },
    accountDescription: { uk: 'У Account Console можна змінити ваші особисті дані, включно з біометрією/пін-кодами та іншими ключами.', en: 'In the Account Console you can update your personal details, including biometrics.' },
    passkeyOptionalHint: { uk: 'Passkey не обов’язковий: його можна налаштувати будь-коли пізніше в Account Console → Signing in → Set up passkey.', en: 'A passkey is optional: you can set one up any time later in Account Console → Signing in → Set up passkey.' },
    vaultWebauthn: { uk: 'Розблокування через Passkey', en: 'Unlock with a passkey' },
    vaultWebauthnDesc: { uk: 'Прив’яжіть біометрію або PIN цього пристрою, щоб розблоковувати Vault без введення Passphrase. Зберігається лише в цьому браузері; Passphrase на сервер не надсилається.', en: 'Bind this device’s biometrics or PIN to unlock the vault without typing your passphrase. Stored only in this browser; the passphrase is never sent to the server.' },
    vaultWebauthnPassLabel: { uk: 'Підтвердіть Vault Passphrase, щоб увімкнути', en: 'Confirm your Vault passphrase to enable' },
    vaultWebauthnEnable: { uk: 'Увімкнути Passkey', en: 'Enable passkey' },
    vaultWebauthnDisable: { uk: 'Вимкнути на цьому пристрої', en: 'Disable on this device' },
    vaultWebauthnEnrolled: { uk: 'Увімкнено на цьому пристрої {date}.', en: 'Enabled on this device {date}.' },
    vaultWebauthnEnabledOk: { uk: 'Passkey-розблокування увімкнено.', en: 'Passkey unlock enabled.' },
    vaultWebauthnDisabled: { uk: 'Passkey-розблокування вимкнено на цьому пристрої.', en: 'Passkey unlock disabled on this device.' },
    vaultWebauthnWrongPass: { uk: 'Невірний Vault Passphrase.', en: 'Incorrect Vault passphrase.' },
    vaultWebauthnUnsupported: { uk: 'Цей браузер або пристрій не підтримує Passkey.', en: 'This browser or device does not support passkeys.' },
    tosCheckboxLabel: { uk: 'Я прочитав(-ла) і погоджуюсь з Умовами надання послуг та Ліцензійною угодою (EULA)', en: 'I have read and agree to the Terms of Service and the End User License Agreement (EULA)' },
    tosReview: { uk: 'Переглянути', en: 'Review' },
    tosDialogTitle: { uk: 'Умови надання послуг', en: 'Terms of Service' },
    tosAccept: { uk: 'Погоджуюсь', en: 'I agree' },
    tosClose: { uk: 'Закрити', en: 'Close' },
    tosRequired: { uk: 'Щоб створити Vault Passphrase, підтвердіть Умови надання послуг та EULA.', en: 'To create a Vault passphrase, confirm the Terms of Service and EULA.' },
    eulaReview: { uk: 'Переглянути EULA', en: 'Review EULA' },
    eulaDialogTitle: { uk: 'Ліцензійна угода з кінцевим користувачем (EULA)', en: 'End User License Agreement (EULA)' },
    eulaAccept: { uk: 'Погоджуюсь', en: 'I agree' },
    eulaClose: { uk: 'Закрити', en: 'Close' },
    legal: { uk: 'Правова інформація', en: 'Legal' },
    legalDescription: { uk: 'Повні тексти документів, які Ви прийняли під час створення Vault.', en: 'Full text of the documents you accepted when creating your vault.' },
    viewTos: { uk: 'Переглянути Умови надання послуг', en: 'View Terms of Service' },
    viewEula: { uk: 'Переглянути EULA', en: 'View EULA' },
    name: { uk: 'Назва', en: 'Name' }, username: { uk: 'Ім’я користувача / логін', en: 'Username / login' }, password: { uk: 'Пароль', en: 'Password' },
    notes: { uk: 'Нотатки', en: 'Notes' }, itemType: { uk: 'Тип запису', en: 'Item type' }, collection: { uk: 'Колекція', en: 'Collection' },
    sharedAccess: { uk: 'Спільний доступ', en: 'Shared access' }, externalShare: { uk: 'Зовнішній спільний доступ', en: 'External sharing' },
    cancel: { uk: 'Скасувати', en: 'Cancel' }, save: { uk: 'Зберегти', en: 'Save' }, delete: { uk: 'Видалити', en: 'Delete' },
    copy: { uk: 'Копіювати', en: 'Copy' }, revoke: { uk: 'Відкликати', en: 'Revoke' }, share: { uk: 'Надати доступ', en: 'Share' },
    createLink: { uk: 'Створити посилання', en: 'Create link' }, tagsHelp: { uk: 'Введіть тег і натисніть пробіл, Enter або кому', en: 'Type a tag and press space, Enter or comma' },
    directoryPickerPlaceholder: { uk: 'Користувач або група домену', en: 'Domain user or group' },
    directoryUserPlaceholder: { uk: 'Email колеги', en: 'Colleague email' },
    noKeysForUser: { uk: 'У {user} ще немає ключів — користувач має увійти у vault хоча б раз, або користувача не існує.', en: '{user} has no keys yet — they must sign in to the vault at least once, or the user does not exist.' },
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
    groupHiddenBadge: { uk: 'приховано', en: 'hidden' },
    groupHiddenTooltip: { uk: 'Приховано адміністратором Workspace: користувачі поза адмінами не бачать цю групу', en: 'Hidden by workspace admin: non-admin users cannot see this group' },
} as const;

type Key = keyof typeof messages;
type Translation = { language: Language; setLanguage: (language: Language) => void; t: (key: Key, values?: Values) => string };
const I18nContext = createContext<Translation | null>(null);
const storageKey = 'kse-pm-language';

/** Non-hook language lookup for pure modules (reads the persisted choice).
 * Components should prefer useI18n(); this exists for plain .ts helpers. */
export function tr(uk: string, en: string): string {
    return localStorage.getItem(storageKey) === 'en' ? en : uk;
}

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
