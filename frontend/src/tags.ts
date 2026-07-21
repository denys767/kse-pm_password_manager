/** Parse legacy comma-separated metadata into stable display tags. */
export function parseTags(value: string | null | undefined): string[] {
    const known = new Set<string>();
    return (value ?? '').split(',').map((tag) => tag.trim()).filter((tag) => {
        const key = tag.toLocaleLowerCase();
        if (!key || known.has(key)) return false;
        known.add(key); return true;
    });
}

export function serializeTags(tags: string[]): string | null {
    const cleaned = parseTags(tags.join(','));
    return cleaned.length ? cleaned.join(', ') : null;
}

export function collectTags(values: Array<string | null | undefined>) {
    const tags = new Map<string, { name: string; count: number }>();
    values.forEach((value) => parseTags(value).forEach((name) => {
        const key = name.toLocaleLowerCase(); const current = tags.get(key);
        tags.set(key, current ? { ...current, count: current.count + 1 } : { name, count: 1 });
    }));
    return [...tags.values()].sort((a, b) => a.name.localeCompare(b.name));
}
