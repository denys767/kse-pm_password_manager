/** Minimal RFC-4180-ish CSV support for vault import/export.
 * Columns: name,url,username,password,notes,tags */

export interface CsvRow {
    name: string;
    url: string;
    username: string;
    password: string;
    notes: string;
    tags: string;
}

const HEADER: (keyof CsvRow)[] = ['name', 'url', 'username', 'password', 'notes', 'tags'];

function escapeCell(value: string): string {
    return /[",\n\r]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

export function toCsv(rows: CsvRow[]): string {
    const lines = [HEADER.join(',')];
    for (const row of rows) {
        lines.push(HEADER.map((column) => escapeCell(row[column] ?? '')).join(','));
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
    const index = new Map<keyof CsvRow, number>();
    for (const column of HEADER) {
        const at = header.indexOf(column);
        if (at >= 0) {
            index.set(column, at);
        }
    }
    if (!index.has('name') || !index.has('password')) {
        throw new Error('CSV має містити колонки name і password');
    }
    return cells.slice(1).map((line) => {
        const value = (column: keyof CsvRow) => {
            const at = index.get(column);
            return at === undefined ? '' : (line[at] ?? '').trim();
        };
        return {
            name: value('name'),
            url: value('url'),
            username: value('username'),
            password: value('password'),
            notes: value('notes'),
            tags: value('tags'),
        };
    }).filter((r) => r.name && r.password);
}
