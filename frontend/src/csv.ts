/** Minimal RFC-4180-ish CSV support for vault import/export.
 * Sensitive template fields are intentionally present only in this explicit,
 * user-requested plaintext export — never as server-side columns. */
import type { SecretType } from './types';

export interface CsvRow {
    name: string;
    secretType: SecretType;
    url: string;
    username: string;
    password: string;
    notes: string;
    tags: string;
    apiKey: string;
    apiSecret: string;
    sshPrivateKey: string;
    cardNumber: string;
    cardCvv: string;
    cardHolder: string;
    cardExpiry: string;
    totpSeed: string;
}

const HEADER = [
    'name', 'type', 'url', 'username', 'password', 'notes', 'tags', 'apiKey', 'apiSecret',
    'sshPrivateKey', 'cardNumber', 'cardCvv', 'cardHolder', 'cardExpiry', 'totpSeed',
];

const TYPES: SecretType[] = ['LOGIN', 'API_CREDENTIALS', 'SSH_KEY', 'CARD', 'SECURE_NOTE'];

function escapeCell(value: string): string {
    return /[",\n\r]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

export function toCsv(rows: CsvRow[]): string {
    const lines = [HEADER.join(',')];
    for (const row of rows) {
        lines.push(HEADER.map((column) => escapeCell(
            column === 'type' ? row.secretType : row[column as keyof CsvRow] ?? '',
        )).join(','));
    }
    return lines.join('\r\n');
}

export function parseCsv(text: string): CsvRow[] {
    const cells: string[][] = [];
    let row: string[] = [];
    let cell = '';
    let inQuotes = false;
    for (let i = 0; i < text.length; i++) {
        const ch = text[i];
        if (inQuotes) {
            if (ch === '"' && text[i + 1] === '"') {
                cell += '"';
                i++;
            } else if (ch === '"') {
                inQuotes = false;
            } else {
                cell += ch;
            }
        } else if (ch === '"') {
            inQuotes = true;
        } else if (ch === ',') {
            row.push(cell);
            cell = '';
        } else if (ch === '\n' || ch === '\r') {
            if (ch === '\r' && text[i + 1] === '\n') {
                i++;
            }
            row.push(cell);
            cell = '';
            if (row.some((c) => c !== '')) {
                cells.push(row);
            }
            row = [];
        } else {
            cell += ch;
        }
    }
    row.push(cell);
    if (row.some((c) => c !== '')) {
        cells.push(row);
    }
    if (cells.length === 0) {
        return [];
    }
    // Header row: map columns by name; unknown columns are ignored.
    const header = cells[0].map((h) => h.trim().toLowerCase());
    const index = new Map<string, number>();
    for (const column of HEADER) {
        const at = header.indexOf(column.toLowerCase());
        if (at >= 0) {
            index.set(column.toLowerCase(), at);
        }
    }
    if (!index.has('name')) {
        throw new Error('CSV має містити колонку name');
    }
    return cells.slice(1).map((line) => {
        const value = (column: string) => {
            const at = index.get(column.toLowerCase());
            return at === undefined ? '' : (line[at] ?? '').trim();
        };
        const rawType = value('type').toUpperCase();
        const secretType = TYPES.includes(rawType as SecretType) ? rawType as SecretType : 'LOGIN';
        return {
            name: value('name'),
            secretType,
            url: value('url'),
            username: value('username'),
            password: value('password'),
            notes: value('notes'),
            tags: value('tags'),
            apiKey: value('apiKey'),
            apiSecret: value('apiSecret'),
            sshPrivateKey: value('sshPrivateKey'),
            cardNumber: value('cardNumber'),
            cardCvv: value('cardCvv'),
            cardHolder: value('cardHolder'),
            cardExpiry: value('cardExpiry'),
            totpSeed: value('totpSeed'),
        };
    }).filter((r) => r.name && (r.secretType !== 'LOGIN' || Boolean(r.password)));
}
