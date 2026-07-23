/** Password generation, strength estimation and HaveIBeenPwned breach check.
 * Everything runs client-side; HIBP uses k-anonymity (only the first five hex
 * chars of the SHA-1 ever leave the browser). */
import { tr } from './i18n';

const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SYMBOLS = '!@#$%^&*()-_=+[]{};:,.<>?';

export interface GeneratorOptions {
    length?: number;
    symbols?: boolean;
}

export function generatePassword({ length = 20, symbols = true }: GeneratorOptions = {}): string {
    const classes = symbols ? [LOWER, UPPER, DIGITS, SYMBOLS] : [LOWER, UPPER, DIGITS];
    const pool = classes.join('');
    const out: string[] = [];
    // Guarantee at least one character from each class, then fill randomly.
    for (const cls of classes) {
        out.push(cls[randomBelow(cls.length)]);
    }
    while (out.length < length) {
        out.push(pool[randomBelow(pool.length)]);
    }
    // Fisher-Yates shuffle so the guaranteed characters aren't predictable.
    for (let i = out.length - 1; i > 0; i--) {
        const j = randomBelow(i + 1);
        [out[i], out[j]] = [out[j], out[i]];
    }
    return out.join('');
}

/** Unbiased random int in [0, max) via rejection sampling. */
function randomBelow(max: number): number {
    const limit = Math.floor(256 / max) * max;
    const byte = new Uint8Array(1);
    for (;;) {
        crypto.getRandomValues(byte);
        if (byte[0] < limit) {
            return byte[0] % max;
        }
    }
}

export interface Strength {
    /** 0..4 */
    score: number;
    label: string;
    bits: number;
}

/** Rough entropy estimate from length and character classes. A dictionary
 * estimator (zxcvbn) is planned — this deliberately stays dependency-free. */
export function estimateStrength(password: string): Strength {
    if (!password) {
        return { score: 0, label: '', bits: 0 };
    }
    let pool = 0;
    if (/[a-z]/.test(password)) pool += 26;
    if (/[A-Z]/.test(password)) pool += 26;
    if (/[0-9]/.test(password)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(password)) pool += 30;
    let bits = password.length * Math.log2(pool || 1);
    // Crude penalties for the most common weak shapes.
    if (/^[a-zA-Z]+[0-9]{1,4}$/.test(password)) bits *= 0.6;
    if (/(.)\1{2,}/.test(password)) bits *= 0.7;
    const score = bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
    const labels = localStorage.getItem('kse-pm-language') === 'en'
        ? ['very weak', 'weak', 'medium', 'strong', 'very strong']
        : ['дуже слабкий', 'слабкий', 'середній', 'сильний', 'дуже сильний'];
    return { score, label: labels[score], bits: Math.round(bits) };
}

/** Returns how many times the password appears in known breaches (0 = clean).
 * k-anonymity: only the 5-char SHA-1 prefix is sent to HIBP. */
export async function hibpBreachCount(password: string): Promise<number> {
    const hex = await sha1Hex(password);
    const prefix = hex.slice(0, 5);
    const suffix = hex.slice(5);
    const matches = await hibpRange(prefix);
    return matches.get(suffix) ?? 0;
}

/**
 * Checks many already-decrypted passwords without exposing them. Passwords are
 * SHA-1 hashed locally, then equal five-character prefixes share one HIBP
 * range request. Requests are deliberately sequential and throttled so opening
 * the dashboard does not burst the public HIBP service.
 */
export async function hibpBreachCounts(passwords: string[]): Promise<Map<string, number>> {
    const hashes = await Promise.all(passwords.map(async (password) => ({
        password,
        hash: await sha1Hex(password),
    })));
    const prefixes = [...new Set(hashes.map(({ hash }) => hash.slice(0, 5)))];
    const ranges = new Map<string, Map<string, number>>();
    for (let i = 0; i < prefixes.length; i++) {
        if (i > 0) {
            await new Promise<void>((resolve) => window.setTimeout(resolve, 120));
        }
        ranges.set(prefixes[i], await hibpRange(prefixes[i]));
    }
    return new Map(hashes.map(({ password, hash }) => [
        password,
        ranges.get(hash.slice(0, 5))?.get(hash.slice(5)) ?? 0,
    ]));
}

async function sha1Hex(password: string): Promise<string> {
    const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
    return [...new Uint8Array(digest)]
        .map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function hibpRange(prefix: string): Promise<Map<string, number>> {
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
        headers: { 'Add-Padding': 'true' },
    });
    if (!response.ok) {
        throw new Error(tr(`HIBP недоступний (HTTP ${response.status})`, `HIBP is unavailable (HTTP ${response.status})`));
    }
    const body = await response.text();
    const matches = new Map<string, number>();
    for (const line of body.split('\n')) {
        const [candidate, count] = line.trim().split(':');
        if (candidate && count) {
            matches.set(candidate, parseInt(count, 10) || 0);
        }
    }
    return matches;
}
