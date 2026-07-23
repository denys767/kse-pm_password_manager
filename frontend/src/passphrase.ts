import { tr } from './i18n';
import type { Me } from './types';

export interface PassphraseAssessment {
    score: number;
    label: string;
    message: string;
}

const COMMON = new Set(['admin', 'password', 'passphrase', 'qwerty', 'letmein', 'welcome', 'kse', 'google', 'football', 'iloveyou', 'monkey', 'dragon', 'secret', '123456']);

export async function assessPassphrase(value: string, user: Me): Promise<PassphraseAssessment> {
    if (value.length < 12) return { score: 0, label: tr('занадто коротка', 'too short'), message: tr('Використайте щонайменше 12 символів.', 'Use at least 12 characters.') };
    const lowered = value.toLowerCase();
    const personal = [user.email, user.displayName, user.email.split('@')[0], user.email.split('@')[1]]
        .filter(Boolean).map((v) => v.toLowerCase());
    if (personal.some((v) => v.length > 2 && lowered.includes(v))) {
        return { score: 0, label: tr('містить персональні дані', 'contains personal data'), message: tr('Не використовуйте email, ім’я або домен.', 'Do not use your email, name, or domain.') };
    }
    const words = value.toLowerCase().split(/[\s\-_.]+/).filter(Boolean);
    const hasCommon = words.some((word) => COMMON.has(word)) || /(.)\1{3,}/.test(lowered)
        || /(?:0123|1234|abcd|qwerty)/.test(lowered);
    if (hasCommon) return { score: 1, label: tr('легко вгадується', 'easily guessed'), message: tr('Уникайте поширених слів, повторів і послідовностей.', 'Avoid common words, repeats, and sequences.') };
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((r) => r.test(value)).length;
    const unique = new Set(value).size;
    const score = value.length >= 20 && unique >= 10 ? 4 : value.length >= 16 && classes >= 2 ? 3 : value.length >= 14 && unique >= 8 ? 3 : 2;
    const labels = tr('дуже слабка,слабка,середня,сильна,дуже сильна', 'very weak,weak,medium,strong,very strong').split(',');
    return { score, label: labels[score], message: score >= 3 ? tr('Добре. Використовуйте унікальну фразу, яку зможете згадати.', 'Good. Use a unique phrase you can remember.') : tr('Додайте більше випадкових слів або символів.', 'Add more random words or characters.') };
}
