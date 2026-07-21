import jsQR from 'jsqr';
import { matchesOrigin } from './origin';
import type { PasswordItem } from './types';

const send = <T>(message: unknown): Promise<T> => chrome.runtime.sendMessage(message) as Promise<T>;

/** Small shadow-DOM host so injected UI never inherits/leaks page styles. */
function toast(text: string): void {
    const host = document.createElement('div');
    host.style.cssText = 'position:fixed;top:16px;right:16px;z-index:2147483647;';
    const root = host.attachShadow({ mode: 'closed' });
    root.innerHTML = `<style>
        div { font: 13px/1.4 system-ui, sans-serif; background:#182033; color:#fff; padding:10px 14px;
              border-radius:6px; box-shadow:0 4px 16px rgba(0,0,0,.25); max-width:280px; }
    </style><div>${text.replace(/[<>]/g, '')}</div>`;
    document.documentElement.appendChild(host);
    setTimeout(() => host.remove(), 4000);
}

function passwordInputs(): HTMLInputElement[] {
    return [...document.querySelectorAll<HTMLInputElement>('input[type="password"]')]
        .filter((el) => el.offsetParent !== null && !el.disabled);
}

function generatePassword(length = 20): string {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-+=';
    const random = crypto.getRandomValues(new Uint32Array(length));
    return [...random].map((value) => alphabet[value % alphabet.length]).join('');
}

function setInput(input: HTMLInputElement, value: string): void {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    setter?.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
}

/** Offers a generated password only on sign-up/new-password forms; it is saved only after submit. */
function offerGeneratedPassword(): void {
    const inputs = passwordInputs().filter((input) => input.autocomplete.includes('new-password'));
    if (inputs.length === 0 || document.querySelector('[data-kse-pm-generate]')) return;
    const anchor = inputs[0];
    const button = document.createElement('button');
    button.type = 'button'; button.dataset.ksePmGenerate = '1'; button.textContent = 'Generate secure password';
    button.title = 'Generate and fill a strong password';
    button.style.cssText = 'position:absolute;z-index:2147483647;cursor:pointer;border:0;background:#003964;color:#fff;border-radius:4px;padding:4px 7px;font:12px system-ui,sans-serif;';
    const place = () => { const rect = anchor.getBoundingClientRect(); button.style.top = `${rect.top + window.scrollY - 30}px`; button.style.left = `${rect.right + window.scrollX - 164}px`; };
    place(); window.addEventListener('resize', place); window.addEventListener('scroll', place, true);
    button.addEventListener('click', () => {
        const password = generatePassword();
        inputs.forEach((input) => setInput(input, password));
        toast('A strong password was filled. It will be offered for saving after registration.');
    });
    document.body.appendChild(button);
}

/** Inline "fill" affordance next to any password field that matches a saved item for this origin. */
async function offerAutofill(): Promise<void> {
    let items: PasswordItem[];
    try { items = await send<PasswordItem[]>({ type: 'items' }); } catch { return; }
    const matches = items.filter((item) => matchesOrigin(item.url, location.href));
    if (matches.length === 0) return;
    for (const input of passwordInputs()) {
        if (input.dataset.ksePmMarked) continue;
        input.dataset.ksePmMarked = '1';
        const button = document.createElement('button');
        button.type = 'button';
        button.textContent = '🔑';
        button.title = 'Заповнити з KSE Password Manager';
        button.style.cssText = 'position:absolute;z-index:2147483647;cursor:pointer;border:0;background:#eef0f5;'
            + 'border-radius:4px;padding:2px 6px;font-size:12px;';
        const place = () => {
            const rect = input.getBoundingClientRect();
            button.style.top = `${rect.top + window.scrollY + rect.height / 2 - 10}px`;
            button.style.left = `${rect.right + window.scrollX - 28}px`;
        };
        place();
        window.addEventListener('resize', place);
        window.addEventListener('scroll', place, true);
        button.addEventListener('click', async (event) => {
            event.preventDefault();
            const item = matches.length === 1 ? matches[0] : matches[0]; // MVP: first match; open the popup for a picker with several.
            try { await send({ type: 'autofill', item }); } catch (e) { toast((e as Error).message); }
        });
        document.body.appendChild(button);
    }
}

/** Captures newly-typed credentials on submit and offers to save them as a new vault item. */
function watchForNewCredentials(): void {
    document.addEventListener('submit', (event) => {
        const form = event.target as HTMLFormElement;
        const passwordInput = form?.querySelector<HTMLInputElement>('input[type="password"]');
        if (!passwordInput?.value) return;
        const usernameInput = [...form.querySelectorAll<HTMLInputElement>('input')]
            .find((el) => el.type === 'email' || el.type === 'text' || el.autocomplete.includes('username'));
        const url = location.origin + location.pathname;
        const username = usernameInput?.value ?? '';
        const password = passwordInput.value;
        void send<{ saved: boolean }>({ type: 'save-credentials', url, username, password }).then((result) => {
            if (result.saved) toast('Пароль збережено у KSE Password Manager.');
        }).catch((e: Error) => {
            if (e.message.includes('заблокован')) toast('KSE Password Manager: розблокуйте vault, щоб зберігати нові паролі.');
        });
    }, true);
}

/** Decodes a QR code (e.g. a site's 2FA setup screen) into an otpauth:// URI, scanning every image/canvas on the page. */
async function scanQrOnPage(): Promise<string | null> {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) return null;
    const candidates: (HTMLImageElement | HTMLCanvasElement)[] = [
        ...document.querySelectorAll('img'),
        ...document.querySelectorAll('canvas'),
    ];
    for (const el of candidates) {
        const width = el instanceof HTMLImageElement ? el.naturalWidth : el.width;
        const height = el instanceof HTMLImageElement ? el.naturalHeight : el.height;
        if (!width || !height || width < 40 || height < 40) continue;
        canvas.width = width; canvas.height = height;
        try {
            ctx.clearRect(0, 0, width, height);
            ctx.drawImage(el, 0, 0, width, height);
            const { data } = ctx.getImageData(0, 0, width, height);
            const result = jsQR(data, width, height);
            if (result?.data.toLowerCase().startsWith('otpauth://')) return result.data;
        } catch { /* cross-origin image — canvas is tainted, can't read it; skip */ }
    }
    return null;
}

chrome.runtime.onMessage.addListener((message: unknown, _sender, sendResponse) => {
    const m = message as { type: string };
    if (m.type === 'scan-qr-on-page') {
        scanQrOnPage().then((uri) => sendResponse({ uri })).catch(() => sendResponse({ uri: null }));
        return true;
    }
    return false;
});

void offerAutofill();
void offerGeneratedPassword();
watchForNewCredentials();
