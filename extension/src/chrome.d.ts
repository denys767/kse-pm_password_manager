declare namespace chrome {
    namespace runtime { const lastError: { message?: string } | undefined; const onMessage: { addListener(cb: (message: unknown, sender: unknown, sendResponse: (response: unknown) => void) => boolean | void): void }; function sendMessage(message: unknown): Promise<unknown>; }
    namespace identity { function getRedirectURL(path?: string): string; function launchWebAuthFlow(details: { url: string; interactive: boolean }): Promise<string | undefined>; }
    namespace tabs { function query(queryInfo: { active: boolean; currentWindow: boolean }): Promise<Array<{ id?: number; url?: string }>>; }
    namespace scripting { function executeScript(details: { target: { tabId: number }; func: (...args: any[]) => unknown; args?: unknown[] }): Promise<unknown>; }
    namespace alarms { function create(name: string, alarmInfo: { when: number }): void; const onAlarm: { addListener(cb: (alarm: { name: string }) => void): void }; }
    namespace offscreen { function createDocument(options: { url: string; reasons: string[]; justification: string }): Promise<void>; function hasDocument(): Promise<boolean>; }
}
