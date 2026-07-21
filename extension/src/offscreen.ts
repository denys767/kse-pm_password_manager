chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
    const m = message as { type: string; value?: string };
    if (m.type === 'clipboard-copy' || m.type === 'clipboard-clear') {
        void navigator.clipboard.writeText(m.type === 'clipboard-copy' ? m.value ?? '' : '').then(() => sendResponse({ ok: true }), (error: Error) => sendResponse({ error: error.message }));
        return true;
    }
});
