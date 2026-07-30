declare namespace chrome {
    namespace runtime {
        const lastError: { message?: string } | undefined;
        /** `tab` is present only for messages from a content script; the popup
         * and other extension pages send without one. */
        interface MessageSender {
            origin?: string;
            tab?: { id?: number; url?: string; windowId?: number };
        }
        const onMessage: { addListener(cb: (message: unknown, sender: MessageSender, sendResponse: (response: unknown) => void) => boolean | void): void };
        function sendMessage(message: unknown): Promise<unknown>;
        interface Port {
            sender?: { origin?: string; tab?: { id?: number; windowId?: number } };
            postMessage(message: unknown): void;
            disconnect(): void;
            onMessage: { addListener(cb: (message: unknown, port: Port) => void): void };
            onDisconnect: { addListener(cb: (port: Port) => void): void };
        }
        const onConnectExternal: { addListener(cb: (port: Port) => void): void };
        const onMessageExternal: {
            addListener(cb: (message: unknown, sender: { origin?: string; tab?: { id?: number } }, sendResponse: (response: unknown) => void) => boolean | void): void;
            removeListener(cb: (message: unknown, sender: { origin?: string; tab?: { id?: number } }, sendResponse: (response: unknown) => void) => boolean | void): void;
        };
    }
    namespace tabs {
        function query(queryInfo: { active: boolean; currentWindow: boolean }): Promise<Array<{ id?: number; url?: string }>>;
        function sendMessage(tabId: number, message: unknown): Promise<unknown>;
        function create(properties: { url: string; active?: boolean }): Promise<{ id?: number }>;
        function update(tabId: number, properties: { active?: boolean }): Promise<unknown>;
        function remove(tabId: number): Promise<void>;
        const onRemoved: { addListener(cb: (tabId: number) => void): void; removeListener(cb: (tabId: number) => void): void };
    }
    namespace windows {
        function update(windowId: number, properties: { focused?: boolean }): Promise<unknown>;
    }
    namespace scripting { function executeScript(details: { target: { tabId: number }; func: (...args: any[]) => unknown; args?: unknown[] }): Promise<unknown>; }
    namespace alarms { function create(name: string, alarmInfo: { when?: number; delayInMinutes?: number; periodInMinutes?: number }): void; function clear(name: string): Promise<boolean>; const onAlarm: { addListener(cb: (alarm: { name: string }) => void): void }; }
    namespace storage {
        interface AreaWithAccessLevel {
            get(keys?: string | string[] | null): Promise<Record<string, unknown>>;
            set(items: Record<string, unknown>): Promise<void>;
            remove(keys: string | string[]): Promise<void>;
            setAccessLevel(details: { accessLevel: 'TRUSTED_CONTEXTS' | 'TRUSTED_AND_UNTRUSTED_CONTEXTS' }): Promise<void>;
        }
        const session: AreaWithAccessLevel;
    }
    namespace offscreen { function createDocument(options: { url: string; reasons: string[]; justification: string }): Promise<void>; function hasDocument(): Promise<boolean>; }
    namespace webAuthenticationProxy {
        interface Request { requestId: number; requestDetailsJson: string; }
        function attach(): Promise<string | undefined>; function detach(): Promise<string | undefined>;
        function completeCreateRequest(details: { requestId: number; responseJson?: string; error?: { name: string; message: string } }): Promise<void>;
        function completeGetRequest(details: { requestId: number; responseJson?: string; error?: { name: string; message: string } }): Promise<void>;
        function completeIsUvpaaRequest(details: { requestId: number; isUvpaa: boolean }): Promise<void>;
        const onCreateRequest: { addListener(cb: (request: Request) => void): void };
        const onGetRequest: { addListener(cb: (request: Request) => void): void };
        const onIsUvpaaRequest: { addListener(cb: (request: { requestId: number }) => void): void };
        const onRequestCanceled: { addListener(cb: (requestId: number) => void): void };
    }
}
