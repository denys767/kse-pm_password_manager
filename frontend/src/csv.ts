/** CSV v4 support. Sensitive values only exist in this explicit browser-side
 * export/import flow; the server receives ciphertext commands, never CSV. */
import { tr } from './i18n';
import type { SecretType } from './types';

export type CsvAction = 'create' | 'update' | 'delete';

export interface CsvRow {
    version: string;
    action: CsvAction;
    id: string;
    updatedAt: string;
    name: string;
    secretType: SecretType;
    url: string;
    username: string;
    password: string;
    notes: string;
    tags: string;
    /** Reserved JSON permission metadata. It is rejected until encrypted
     * wrapped-key provisioning can be made atomic with sharing. */
    permissions: string;
    apiKey: string;
    apiSecret: string;
    sshPrivateKey: string;
    sshPublicKey: string;
    databaseType: string;
    databaseHost: string;
    databasePort: string;
    databaseName: string;
    databaseUsername: string;
    databasePassword: string;
    cardNumber: string;
    cardCvv: string;
    cardHolder: string;
    cardExpiry: string;
    totpSeed: string;
    /** Reserved: attachment import needs Drive staging and is never uploaded
     * as plaintext to this endpoint. */
    fileName: string;
    fileData: string;
}

export interface CsvPreview {
    rows: CsvRow[];
    createCount: number;
    updateCount: number;
    deleteCount: number;
    warnings: string[];
}

const HEADER: Array<keyof CsvRow | 'type'> = [
    'version', 'action', 'id', 'updatedAt', 'name', 'type', 'url', 'username', 'password', 'notes', 'tags', 'permissions',
    'apiKey', 'apiSecret', 'sshPrivateKey', 'sshPublicKey',
    'databaseType', 'databaseHost', 'databasePort', 'databaseName', 'databaseUsername', 'databasePassword',
    'cardNumber', 'cardCvv', 'cardHolder', 'cardExpiry', 'totpSeed', 'fileName', 'fileData',
];

const TYPES: SecretType[] = ['LOGIN', 'API_CREDENTIALS', 'SSH_KEY', 'DATABASE', 'CARD', 'SECURE_NOTE'];
const ACTIONS: CsvAction[] = ['create', 'update', 'delete'];

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

/** Parses RFC-4180 CSV without silently treating malformed types/actions as
 * LOGIN/create. Legacy files lacking v4 columns remain create-only imports. */
export function parseCsv(text: string): CsvRow[] {
    return previewCsv(text).rows;
}

export function previewCsv(text: string): CsvPreview {
    const cells = splitCsv(text);
    if (cells.length === 0) return { rows: [], createCount: 0, updateCount: 0, deleteCount: 0, warnings: [] };
    const header = cells[0].map((h) => h.trim().toLowerCase());
    const index = new Map<string, number>();
    for (const column of HEADER) {
        const at = header.indexOf(column.toLowerCase());
        if (at >= 0) index.set(column.toLowerCase(), at);
    }
    if (!index.has('name') && !index.has('id')) throw new Error(tr('CSV має містити колонку name або id', 'The CSV must contain a name or id column'));
    const rows: CsvRow[] = cells.slice(1).map((line, position) => {
        const rowNumber = position + 2;
        const value = (column: string) => {
            const at = index.get(column.toLowerCase());
            return at === undefined ? '' : (line[at] ?? '').trim();
        };
        const actionValue = (value('action') || 'create').toLowerCase();
        if (!ACTIONS.includes(actionValue as CsvAction)) throw new Error(tr(`Рядок ${rowNumber}: невідома action '${actionValue}'`, `Row ${rowNumber}: unknown action '${actionValue}'`));
        const action = actionValue as CsvAction;
        const rawType = (value('type') || 'LOGIN').toUpperCase();
        if (!TYPES.includes(rawType as SecretType)) throw new Error(tr(`Рядок ${rowNumber}: невідомий type '${rawType}'`, `Row ${rowNumber}: unknown type '${rawType}'`));
        const item: CsvRow = {
            version: value('version') || '4', action, id: value('id'), updatedAt: value('updatedAt'),
            name: value('name'), secretType: rawType as SecretType,
            url: value('url'), username: value('username'), password: value('password'), notes: value('notes'), tags: value('tags'),
            permissions: value('permissions'), apiKey: value('apiKey'), apiSecret: value('apiSecret'),
            sshPrivateKey: value('sshPrivateKey'), sshPublicKey: value('sshPublicKey'),
            databaseType: value('databaseType'), databaseHost: value('databaseHost'), databasePort: value('databasePort'),
            databaseName: value('databaseName'), databaseUsername: value('databaseUsername'), databasePassword: value('databasePassword'),
            cardNumber: value('cardNumber'), cardCvv: value('cardCvv'), cardHolder: value('cardHolder'), cardExpiry: value('cardExpiry'),
            totpSeed: value('totpSeed'), fileName: value('fileName'), fileData: value('fileData'),
        };
        if (item.version !== '4') throw new Error(tr(`Рядок ${rowNumber}: підтримується лише CSV version=4`, `Row ${rowNumber}: only CSV version=4 is supported`));
        if (action === 'create' && !item.name) throw new Error(tr(`Рядок ${rowNumber}: create потребує name`, `Row ${rowNumber}: create requires a name`));
        if ((action === 'update' || action === 'delete') && (!item.id || !item.updatedAt)) {
            throw new Error(tr(`Рядок ${rowNumber}: ${action} потребує id та updatedAt з експорту`, `Row ${rowNumber}: ${action} requires id and updatedAt from the export`));
        }
        return item;
    });
    const warnings: string[] = [];
    if (rows.some((row) => row.permissions)) warnings.push('Rows with permission metadata cannot be imported yet: wrapped share keys are required.');
    if (rows.some((row) => row.fileName || row.fileData)) warnings.push('Rows with attachment data cannot be imported yet: encrypted Drive staging is required.');
    return {
        rows,
        createCount: rows.filter((row) => row.action === 'create').length,
        updateCount: rows.filter((row) => row.action === 'update').length,
        deleteCount: rows.filter((row) => row.action === 'delete').length,
        warnings,
    };
}

function splitCsv(text: string): string[][] {
    const cells: string[][] = [];
    let row: string[] = []; let cell = ''; let inQuotes = false;
    for (let i = 0; i < text.length; i++) {
        const ch = text[i];
        if (inQuotes) {
            if (ch === '"' && text[i + 1] === '"') { cell += '"'; i++; }
            else if (ch === '"') inQuotes = false;
            else cell += ch;
        } else if (ch === '"') {
            if (cell) throw new Error('CSV: quote must start at the beginning of a cell');
            inQuotes = true;
        } else if (ch === ',') { row.push(cell); cell = ''; }
        else if (ch === '\n' || ch === '\r') {
            if (ch === '\r' && text[i + 1] === '\n') i++;
            row.push(cell); cell = '';
            if (row.some((c) => c !== '')) cells.push(row);
            row = [];
        } else cell += ch;
    }
    if (inQuotes) throw new Error('CSV: unclosed quoted cell');
    row.push(cell);
    if (row.some((c) => c !== '')) cells.push(row);
    return cells;
}
