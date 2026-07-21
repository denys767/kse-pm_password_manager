/** Strict origin equality only: scheme, host and port must all match. */
export function matchesOrigin(itemUrl: string | null, tabUrl: string | undefined): boolean {
    if (!itemUrl || !tabUrl) return false;
    try {
        const item = new URL(itemUrl);
        const tab = new URL(tabUrl);
        return (item.protocol === 'http:' || item.protocol === 'https:')
            && (tab.protocol === 'http:' || tab.protocol === 'https:')
            && item.origin === tab.origin;
    } catch {
        return false;
    }
}
