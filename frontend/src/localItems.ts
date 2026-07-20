import type { PasswordItem } from './types';

/** Local-only items live in localStorage, encrypted with their own item key
 * which is in turn wrapped with the KEK (see crypto.ts). */

const key = (email: string) => `pm.local.${email}`;

export function loadLocalItems(email: string): PasswordItem[] {
    try {
        return JSON.parse(localStorage.getItem(key(email)) || '[]');
    } catch {
        return [];
    }
}

export function saveLocalItems(email: string, items: PasswordItem[]): void {
    localStorage.setItem(key(email), JSON.stringify(items));
}

export function clearLocalItems(email: string): void {
    localStorage.removeItem(key(email));
}
