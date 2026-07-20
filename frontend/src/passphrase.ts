import type { Me } from './types';

export interface PassphraseAssessment {
    score: number;
    label: string;
    message: string;
}

const COMMON = new Set(['admin', 'password', 'passphrase', 'qwerty', 'letmein', 'welcome', 'kse', 'google', 'football', 'iloveyou', 'monkey', 'dragon', 'secret', '123456']);

export async function assessPassphrase(value: string, user: Me): Promise<PassphraseAssessment> {
    if (value.length < 12) return { score: 0, label: 'занадто коротка', message: 'Використайте щонайменше 12 символів.' };
    const lowered = value.toLowerCase();
    const personal = [user.email, user.displayName, user.email.split('@')[0], user.email.split('@')[1]]
        .filter(Boolean).map((v) => v.toLowerCase());
    if (personal.some((v) => v.length > 2 && lowered.includes(v))) {
        return { score: 0, label: 'містить персональні дані', message: 'Не використовуйте email, ім’я або домен.' };
    }
    const words = value.toLowerCase().split(/[\s\-_.]+/).filter(Boolean);
    const hasCommon = words.some((word) => COMMON.has(word)) || /(.)\1{3,}/.test(lowered)
        || /(?:0123|1234|abcd|qwerty)/.test(lowered);
    if (hasCommon) return { score: 1, label: 'легко вгадується', message: 'Уникайте поширених слів, повторів і послідовностей.' };
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((r) => r.test(value)).length;
    const unique = new Set(value).size;
    const score = value.length >= 20 && unique >= 10 ? 4 : value.length >= 16 && classes >= 2 ? 3 : value.length >= 14 && unique >= 8 ? 3 : 2;
    const labels = ['дуже слабка', 'слабка', 'середня', 'сильна', 'дуже сильна'];
    return { score, label: labels[score], message: score >= 3 ? 'Добре. Використовуйте унікальну фразу, яку зможете згадати.' : 'Додайте більше випадкових слів або символів.' };
}
