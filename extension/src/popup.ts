import { matchesOrigin } from './origin';
import type { PasswordItem } from './types';
import './popup.css';

const app = document.querySelector<HTMLDivElement>('#app')!;
let items: PasswordItem[] = [];
let activeUrl: string | undefined;
const send = async <T>(message: unknown): Promise<T> => {
    const result = await chrome.runtime.sendMessage(message) as T & { error?: string };
    if (result?.error) throw new Error(result.error);
    return result;
};
const escape = (value: string) => value.replace(/[&<>'"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c]!));
function error(message: string): void { document.querySelector<HTMLElement>('#status')!.textContent = message; }
function renderItems(query = ''): void {
    const matching = items.filter((item) => matchesOrigin(item.url, activeUrl)).filter((item) => `${item.name} ${item.username ?? ''} ${item.url ?? ''}`.toLowerCase().includes(query.toLowerCase()));
    const list = document.querySelector<HTMLDivElement>('#items')!;
    list.innerHTML = matching.length ? matching.map((item) => `<article><strong>${escape(item.name)}</strong><small>${escape(item.username ?? '')}</small><small>${escape(item.url ?? '')}</small><div><button data-action="fill" data-id="${item.id}">Fill</button><button data-action="copy" data-id="${item.id}">Copy</button></div></article>`).join('') : '<p class="empty">Немає записів для точного origin цієї вкладки.</p>';
    list.querySelectorAll<HTMLButtonElement>('button').forEach((button) => button.addEventListener('click', () => void act(button.dataset.action!, button.dataset.id!)));
}
async function act(action: string, id: string): Promise<void> {
    try {
        const item = items.find((value) => value.id === id)!;
        if (action === 'fill') await send({ type: 'autofill', item }); else await send({ type: 'copy', item });
        error(action === 'fill' ? 'Поля заповнено.' : 'Пароль скопійовано; він буде очищений автоматично.');
    } catch (e) { error((e as Error).message); }
}
async function vault(): Promise<void> {
    const status = await send<{ loggedIn: boolean; unlocked: boolean }>({ type: 'status' });
    if (!status.loggedIn) { app.innerHTML = '<h1>KSE Vault</h1><p id="status">Увійдіть у корпоративний Keycloak.</p><button id="login">Sign in</button>'; document.querySelector('#login')!.addEventListener('click', async () => { try { await send({ type: 'login' }); await vault(); } catch (e) { error((e as Error).message); } }); return; }
    if (!status.unlocked) { app.innerHTML = '<h1>KSE Vault</h1><p id="status">Passphrase не залишає extension.</p><form id="unlock"><input id="passphrase" type="password" autocomplete="current-password" placeholder="Vault passphrase" required /><button>Unlock</button></form>'; document.querySelector<HTMLFormElement>('#unlock')!.addEventListener('submit', async (event) => { event.preventDefault(); try { await send({ type: 'unlock', passphrase: document.querySelector<HTMLInputElement>('#passphrase')!.value }); await vault(); } catch (e) { error((e as Error).message); } }); return; }
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true }); activeUrl = tab?.url;
    items = await send<PasswordItem[]>({ type: 'items' });
    app.innerHTML = '<header><h1>KSE Vault</h1><button id="lock" class="quiet">Lock</button></header><p id="status">Показано лише записи з точним збігом origin.</p><input id="search" type="search" placeholder="Пошук записів" autofocus /><section id="items"></section>';
    document.querySelector('#lock')!.addEventListener('click', async () => { await send({ type: 'lock' }); await vault(); });
    document.querySelector<HTMLInputElement>('#search')!.addEventListener('input', (event) => renderItems((event.target as HTMLInputElement).value));
    renderItems();
}
void vault().catch((e: Error) => { app.innerHTML = `<p id="status">${escape(e.message)}</p>`; });
