import jsQR from 'jsqr';
import type { AutofillCandidatesResult } from './types';

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

/**
 * The account picker.
 *
 * This used to be a single 🔑 button that filled `matches[0]` — so on any site
 * where you have more than one account, it filled the wrong one and there was
 * no way to say which you meant. It also only ever reached the password field.
 * Now every match is listed by username, and choosing one fills the username
 * and the password together.
 */
let openPicker: HTMLElement | undefined;
let openPickerAnchor: HTMLInputElement | undefined;
let blurTimer: ReturnType<typeof setTimeout> | undefined;

function closePicker(): void {
    if (blurTimer !== undefined) { clearTimeout(blurTimer); blurTimer = undefined; }
    openPicker?.remove();
    openPicker = undefined;
    openPickerAnchor = undefined;
}

/** Pure so the geometry can be unit-tested without a DOM. */
export function pickerPosition(rect: { top: number; bottom: number; left: number; width: number },
    viewport: { width: number; height: number }): { top: number; left: number; minWidth: number } {
    const minWidth = Math.max(rect.width, 220);
    const left = Math.min(Math.max(rect.left, 4), Math.max(viewport.width - minWidth - 4, 4));
    const top = rect.bottom + 2 <= viewport.height ? rect.bottom + 2 : Math.max(rect.top - 4, 4);
    return { top, left, minWidth };
}

function reposition(): void {
    if (!openPicker || !openPickerAnchor) return;
    if (!openPickerAnchor.isConnected) { closePicker(); return; }
    const rect = openPickerAnchor.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0) { closePicker(); return; }
    const { top, left, minWidth } = pickerPosition(rect, { width: window.innerWidth, height: window.innerHeight });
    openPicker.style.top = `${top}px`;
    openPicker.style.left = `${left}px`;
    openPicker.style.minWidth = `${minWidth}px`;
}

/** Locked shows a single row with no account names — showing usernames for a
 *  locked vault would defeat the point of locking it. */
function showPicker(anchor: HTMLInputElement, result: AutofillCandidatesResult): void {
    closePicker();
    const host = document.createElement('div');
    const rect = anchor.getBoundingClientRect();
    const { top, left, minWidth } = pickerPosition(rect, { width: window.innerWidth, height: window.innerHeight });
    host.style.cssText = `position:fixed;z-index:2147483647;top:${top}px;left:${left}px;min-width:${minWidth}px;`;
    // Losing focus to the picker itself must not trigger the input's blur-close.
    host.addEventListener('mousedown', (event) => event.preventDefault());
    const root = host.attachShadow({ mode: 'closed' });
    const options = result.locked
        ? `<button type="button" data-locked="1">
            <span class="who">Сховище заблоковане</span><span class="what">Натисніть, щоб розблокувати</span>
        </button>`
        : result.candidates.map((candidate, index) => {
            const label = candidate.username || candidate.name;
            const secondary = candidate.username ? candidate.name : location.hostname;
            return `<button type="button" data-index="${index}">
                <span class="who">${escapeText(label)}</span><span class="what">${escapeText(secondary)}</span>
            </button>`;
        }).join('');
    root.innerHTML = `<style>
        .menu { font: 13px/1.35 system-ui, sans-serif; background:#fff; color:#182033; border:1px solid #d5d9e3;
                border-radius:8px; box-shadow:0 8px 24px rgba(0,0,0,.16); overflow:hidden; }
        .head { padding:6px 10px; font-size:11px; text-transform:uppercase; letter-spacing:.04em;
                color:#6b7280; background:#f6f7fa; border-bottom:1px solid #eceef3; }
        button { display:flex; flex-direction:column; gap:1px; width:100%; text-align:left; border:0;
                 background:none; padding:7px 10px; cursor:pointer; }
        button:hover, button:focus { background:#eef2fb; outline:none; }
        .who { font-weight:600; }
        .what { font-size:11px; color:#6b7280; }
    </style><div class="menu"><div class="head">KSE Password Manager</div>${options}</div>`;
    root.querySelectorAll<HTMLButtonElement>('button').forEach((button) => {
        button.addEventListener('click', () => {
            closePicker();
            if (button.dataset.locked) {
                void send({ type: 'unlock-via-app' }).catch((e: Error) => toast(e.message));
                return;
            }
            const chosen = result.candidates[Number(button.dataset.index)];
            // By id: the page must not be handed the record itself.
            void send({ type: 'autofill', itemId: chosen.id }).catch((e: Error) => toast(e.message));
        });
    });
    document.documentElement.appendChild(host);
    openPicker = host;
    openPickerAnchor = anchor;
}

function escapeText(value: string): string {
    return value.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
}

async function offerAutofill(): Promise<void> {
    let cached: AutofillCandidatesResult | undefined;
    let candidatesAt = 0;
    const CACHE_MS = 30_000;
    const loginField = (el: HTMLInputElement) => el.offsetParent !== null && !el.disabled && !el.readOnly
        && (el.type === 'password' || el.type === 'email'
            || el.autocomplete.includes('username') || el.autocomplete.includes('email'));

    document.addEventListener('focusin', (event) => {
        const input = event.target as HTMLInputElement;
        if (!(input instanceof HTMLInputElement) || !loginField(input)) return;
        if (blurTimer !== undefined) { clearTimeout(blurTimer); blurTimer = undefined; }
        void (async () => {
            if (!cached || Date.now() - candidatesAt > CACHE_MS) {
                try { cached = await send<AutofillCandidatesResult>({ type: 'autofill-candidates', url: location.href }); candidatesAt = Date.now(); }
                catch { return; }
            }
            if (cached.hasMatch && document.activeElement === input) showPicker(input, cached);
        })();
    });
    document.addEventListener('focusout', (event) => {
        const input = event.target as HTMLInputElement;
        if (!(input instanceof HTMLInputElement) || input !== openPickerAnchor) return;
        // Delayed and re-checked: the picker's own mousedown guard keeps focus
        // on the field when a row is clicked, but some sites re-focus
        // asynchronously (label wrappers, floating-label libs) — give that a
        // beat before deciding the field truly lost focus.
        blurTimer = setTimeout(() => {
            blurTimer = undefined;
            if (document.activeElement !== openPickerAnchor) closePicker();
        }, 150);
    });
    document.addEventListener('keydown', (event) => { if (event.key === 'Escape') closePicker(); });
    window.addEventListener('scroll', () => requestAnimationFrame(reposition), true);
    window.addEventListener('resize', () => requestAnimationFrame(reposition));
}

/** Captures newly-typed credentials on submit and offers to save them as a new vault item. */
function watchForNewCredentials(): void {
    document.addEventListener('submit', (event) => {
        const form = event.target as HTMLFormElement;
        const passwordInput = form?.querySelector<HTMLInputElement>('input[type="password"]');
        if (!passwordInput?.value) return;
        // One user gesture, one save. A double-clicked button, or a site that
        // re-submits its own form, otherwise sent two capture messages and
        // created two identical records.
        if (form.dataset.ksePmSubmitted) return;
        form.dataset.ksePmSubmitted = '1';
        setTimeout(() => delete form.dataset.ksePmSubmitted, 2000);
        const url = location.origin + location.pathname;
        const username = submittedUsername(form);
        const password = passwordInput.value;
        void send<{ saved: boolean }>({ type: 'save-credentials', url, username, password }).then((result) => {
            if (result.saved) toast('Пароль збережено у KSE Password Manager.');
        }).catch((e: Error) => {
            if (e.message.includes('заблокован')) toast('KSE Password Manager: розблокуйте vault, щоб зберігати нові паролі.');
        });
    }, true);
}

/**
 * The username that goes with a submitted password.
 *
 * Looking only inside the form misses two-step sign-ins, where the account was
 * entered on a previous screen and the password form contains nothing but the
 * password. Those records were saved with a null username — and an item with no
 * username is one of the reasons autofill later appeared to fill "only the
 * password". Falling back to a filled username-ish field elsewhere on the page
 * recovers most of them.
 */
function submittedUsername(form: HTMLFormElement): string {
    const looksLikeUsername = (el: HTMLInputElement) =>
        el.type === 'email' || el.type === 'text' || el.type === 'tel'
        || el.autocomplete.includes('username') || el.autocomplete.includes('email');
    const inForm = [...form.querySelectorAll<HTMLInputElement>('input')].find((el) => looksLikeUsername(el) && el.value);
    if (inForm) return inForm.value;
    const onPage = [...document.querySelectorAll<HTMLInputElement>('input')]
        .filter((el) => looksLikeUsername(el) && el.value.trim() && !el.disabled);
    return onPage.length === 1 ? onPage[0].value : '';
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
