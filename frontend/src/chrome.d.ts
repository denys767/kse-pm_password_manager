/** Minimal shape of the extension-messaging API Chrome exposes to pages listed
 *  in the extension's externally_connectable — present only when this page is
 *  loaded in a Chromium browser with the KSE Password Manager extension. */
interface ChromeRuntimePort {
    postMessage(message: unknown): void;
    disconnect(): void;
    onMessage: { addListener(cb: (message: unknown) => void): void };
    onDisconnect: { addListener(cb: () => void): void };
}

declare const chrome: {
    runtime?: {
        connect(extensionId: string, connectInfo?: { name?: string }): ChromeRuntimePort;
        sendMessage(extensionId: string, message: unknown): Promise<unknown>;
    };
} | undefined;
