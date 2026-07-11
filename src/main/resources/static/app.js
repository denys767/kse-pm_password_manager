/*
 * KSE Password Manager — frontend shell (MVP).
 *
 * Client-side encryption: the vault passphrase never leaves the browser.
 * A key is derived with PBKDF2 (SHA-256, 210k iterations) and secrets are
 * encrypted with AES-GCM before any request, so the server only ever sees
 * ciphertext. Local-only items are kept (encrypted) in localStorage.
 *
 * Dev mode: identity is sent via X-Dev-User/X-Dev-Roles/X-Dev-Groups headers.
 * In production these headers are ignored — Keycloak issues a JWT instead.
 */

const state = {
    user: null,
    devHeaders: {},
    key: null,
    serverItems: [],
    localItems: [],
    settings: { defaultSyncMode: 'SERVER_SYNCED', clipboardClearSeconds: 20 },
    editing: null, // item currently open in the dialog, null for "add" mode
};

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------- crypto ---

const te = new TextEncoder();
const td = new TextDecoder();

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0));

async function deriveKey(passphrase, saltB64) {
    const material = await crypto.subtle.importKey('raw', te.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: unb64(saltB64), iterations: 210000, hash: 'SHA-256' },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']);
}

async function encrypt(text) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.key, te.encode(text));
    return { ct: b64(ct), iv: b64(iv) };
}

async function decrypt(ctB64, ivB64) {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(ivB64) }, state.key, unb64(ctB64));
    return td.decode(pt);
}

function saltFor(email) {
    const key = `pm.salt.${email}`;
    let salt = localStorage.getItem(key);
    if (!salt) {
        salt = b64(crypto.getRandomValues(new Uint8Array(16)));
        localStorage.setItem(key, salt);
    }
    return salt;
}

/* Verify the passphrase against a locally stored check value so a typo does
 * not silently produce undecryptable items. */
async function verifyPassphrase(email) {
    const key = `pm.check.${email}`;
    const stored = localStorage.getItem(key);
    if (!stored) {
        const enc = await encrypt('kse-pm-check');
        localStorage.setItem(key, JSON.stringify(enc));
        return true;
    }
    try {
        const { ct, iv } = JSON.parse(stored);
        return (await decrypt(ct, iv)) === 'kse-pm-check';
    } catch {
        return false;
    }
}

// ------------------------------------------------------------------- api ---

async function api(path, options = {}) {
    const response = await fetch(path, {
        ...options,
        headers: { 'Content-Type': 'application/json', ...state.devHeaders, ...(options.headers || {}) },
    });
    if (!response.ok) {
        let message = `HTTP ${response.status}`;
        try {
            message = (await response.json()).error || message;
        } catch { /* non-JSON error body */ }
        throw new Error(message);
    }
    return response.status === 204 ? null : response.json();
}

// ---------------------------------------------------------- local storage ---

const localKey = () => `pm.local.${state.user.email}`;

function loadLocalItems() {
    try {
        state.localItems = JSON.parse(localStorage.getItem(localKey()) || '[]');
    } catch {
        state.localItems = [];
    }
}

function saveLocalItems() {
    localStorage.setItem(localKey(), JSON.stringify(state.localItems));
}

// ---------------------------------------------------------------- unlock ---

async function unlock() {
    const email = $('dev-email').value.trim().toLowerCase();
    const passphrase = $('passphrase').value;
    const errorEl = $('unlock-error');
    errorEl.hidden = true;
    if (!email || !passphrase) {
        return showError(errorEl, 'Вкажіть email і passphrase.');
    }
    state.devHeaders = {
        'X-Dev-User': email,
        'X-Dev-Roles': $('dev-roles').value.trim() || 'user',
        'X-Dev-Groups': $('dev-groups').value.trim(),
    };
    try {
        state.user = await api('/api/me');
    } catch (e) {
        return showError(errorEl, `Не вдалося увійти: ${e.message}`);
    }
    state.key = await deriveKey(passphrase, saltFor(state.user.email));
    if (!(await verifyPassphrase(state.user.email))) {
        state.key = null;
        return showError(errorEl, 'Невірний passphrase для цього vault.');
    }
    $('passphrase').value = '';
    $('unlock-screen').hidden = true;
    $('app').hidden = false;
    $('lock-btn').hidden = false;
    $('user-badge').hidden = false;
    $('user-badge').textContent = state.user.email;
    $('audit-tab-btn').hidden = !(state.user.roles.includes('ADMIN') || state.user.roles.includes('SECURITY'));
    await Promise.all([refreshItems(), loadSettings()]);
}

function lock() {
    state.key = null;
    state.user = null;
    state.serverItems = [];
    state.localItems = [];
    $('app').hidden = true;
    $('unlock-screen').hidden = false;
    $('lock-btn').hidden = true;
    $('user-badge').hidden = true;
}

function showError(el, message) {
    el.textContent = message;
    el.hidden = false;
}

// ----------------------------------------------------------------- vault ---

async function refreshItems() {
    state.serverItems = await api('/api/vault/items');
    loadLocalItems();
    renderItems();
}

function allItems() {
    return [...state.serverItems, ...state.localItems];
}

function renderItems() {
    const query = $('search').value.trim().toLowerCase();
    const list = $('item-list');
    list.innerHTML = '';
    const items = allItems().filter((item) =>
        !query || [item.name, item.url, item.username, item.tags]
            .some((v) => v && v.toLowerCase().includes(query)));
    $('empty-state').hidden = items.length > 0;
    for (const item of items.sort((a, b) => a.name.localeCompare(b.name))) {
        const li = document.createElement('li');
        const badges = [];
        if (item.itemType === 'SHARED') badges.push('<span class="badge shared">shared</span>');
        if (item.syncMode === 'LOCAL_ONLY') badges.push('<span class="badge local">local-only</span>');
        if (item.accessRole && item.accessRole !== 'OWNER') {
            badges.push(`<span class="badge">${item.accessRole.toLowerCase()}</span>`);
        }
        li.innerHTML = `
            <div>
                <strong></strong>${badges.join('')}
                <div class="item-meta"></div>
            </div>
            <button class="secondary small">Open</button>`;
        li.querySelector('strong').textContent = item.name;
        li.querySelector('.item-meta').textContent = [item.username, item.url].filter(Boolean).join(' · ');
        li.addEventListener('click', () => openItem(item));
        list.appendChild(li);
    }
}

async function openItem(listItem) {
    let item = listItem;
    if (item.syncMode !== 'LOCAL_ONLY') {
        // Server GET also records the ITEM_VIEWED audit event.
        item = await api(`/api/vault/items/${item.id}`);
    }
    state.editing = item;
    $('dialog-title').textContent = item.name;
    $('f-name').value = item.name;
    $('f-url').value = item.url || '';
    $('f-username').value = item.username || '';
    $('f-password').type = 'password';
    try {
        $('f-password').value = await decrypt(item.encryptedPassword, item.passwordIv);
        $('f-notes').value = item.encryptedNotes ? await decrypt(item.encryptedNotes, item.notesIv) : '';
        $('dialog-error').hidden = true;
    } catch {
        $('f-password').value = '';
        $('f-notes').value = '';
        showError($('dialog-error'),
            'Не вдалося розшифрувати запис цим passphrase (запис створено з іншим ключем).');
    }
    $('f-tags').value = item.tags || '';
    $('f-type').value = item.itemType;
    $('f-sync').checked = item.syncMode !== 'LOCAL_ONLY';

    const isOwner = !item.accessRole || item.accessRole === 'OWNER';
    const canEdit = isOwner || item.accessRole === 'EDITOR';
    for (const id of ['f-name', 'f-url', 'f-username', 'f-password', 'f-notes', 'f-tags']) {
        $(id).readOnly = !canEdit;
    }
    $('f-type').disabled = !isOwner;
    $('save-btn').hidden = !canEdit;
    $('delete-btn').hidden = !isOwner;
    $('copy-pass').hidden = false;
    updateSyncControls();
    $('f-sync').disabled = $('f-sync').disabled || !isOwner;

    $('share-section').hidden = !(isOwner && item.syncMode !== 'LOCAL_ONLY');
    if (!$('share-section').hidden) {
        await renderPermissions();
    }
    $('item-dialog').showModal();
}

function openAddDialog() {
    state.editing = null;
    $('item-form').reset();
    $('dialog-title').textContent = 'Add password';
    $('dialog-error').hidden = true;
    for (const id of ['f-name', 'f-url', 'f-username', 'f-password', 'f-notes', 'f-tags']) {
        $(id).readOnly = false;
    }
    $('f-type').disabled = false;
    $('f-sync').checked = state.settings.defaultSyncMode !== 'LOCAL_ONLY';
    $('save-btn').hidden = false;
    $('delete-btn').hidden = true;
    $('copy-pass').hidden = true;
    $('share-section').hidden = true;
    updateSyncControls();
    $('item-dialog').showModal();
}

/* Shared items must be server-synced — the toggle is forced on and disabled. */
function updateSyncControls() {
    const shared = $('f-type').value === 'SHARED';
    if (shared) {
        $('f-sync').checked = true;
    }
    $('f-sync').disabled = shared;
    $('sync-hint').textContent = shared
        ? 'Shared-записи завжди зберігаються на сервері, інакше sharing не працює.'
        : 'Вимкнено — запис залишиться тільки в цьому браузері (у зашифрованому вигляді).';
}

function confirmLocalOnly() {
    return new Promise((resolve) => {
        const dialog = $('warning-dialog');
        const done = (ok) => {
            dialog.close();
            $('warning-confirm').onclick = null;
            $('warning-cancel').onclick = null;
            resolve(ok);
        };
        $('warning-confirm').onclick = () => done(true);
        $('warning-cancel').onclick = () => done(false);
        dialog.showModal();
    });
}

async function saveItem(event) {
    event.preventDefault();
    const errorEl = $('dialog-error');
    errorEl.hidden = true;
    const wantsSync = $('f-sync').checked;
    const wasLocal = state.editing && state.editing.syncMode === 'LOCAL_ONLY';
    if (!wantsSync && (!state.editing || !wasLocal)) {
        if (!(await confirmLocalOnly())) {
            return;
        }
    }
    try {
        const password = await encrypt($('f-password').value);
        const notes = $('f-notes').value ? await encrypt($('f-notes').value) : null;
        const payload = {
            name: $('f-name').value.trim(),
            url: $('f-url').value.trim() || null,
            username: $('f-username').value.trim() || null,
            encryptedPassword: password.ct,
            passwordIv: password.iv,
            encryptedNotes: notes ? notes.ct : null,
            notesIv: notes ? notes.iv : null,
            tags: $('f-tags').value.trim() || null,
            itemType: $('f-type').value,
            syncMode: 'SERVER_SYNCED',
        };

        if (wantsSync) {
            await saveSynced(payload, wasLocal);
        } else {
            await saveLocalOnly(payload);
        }
        $('item-dialog').close();
        await refreshItems();
    } catch (e) {
        showError(errorEl, e.message);
    }
}

async function saveSynced(payload, wasLocal) {
    if (state.editing && !wasLocal) {
        await api(`/api/vault/items/${state.editing.id}`, { method: 'PUT', body: JSON.stringify(payload) });
        return;
    }
    await api('/api/vault/items', { method: 'POST', body: JSON.stringify(payload) });
    if (state.editing && wasLocal) {
        state.localItems = state.localItems.filter((i) => i.id !== state.editing.id);
        saveLocalItems();
    }
}

async function saveLocalOnly(payload) {
    if (payload.itemType === 'SHARED') {
        throw new Error('Shared-запис не може бути local-only.');
    }
    if (state.editing && state.editing.syncMode !== 'LOCAL_ONLY') {
        // The server removes its copy (with an audit event); we keep it locally.
        await api(`/api/vault/items/${state.editing.id}/sync-mode`, {
            method: 'PATCH',
            body: JSON.stringify({ syncMode: 'LOCAL_ONLY' }),
        });
    }
    const existingId = state.editing && state.editing.syncMode === 'LOCAL_ONLY' ? state.editing.id : null;
    const item = {
        ...payload,
        id: existingId || `local-${crypto.randomUUID()}`,
        syncMode: 'LOCAL_ONLY',
        ownerEmail: state.user.email,
        accessRole: 'OWNER',
        updatedAt: new Date().toISOString(),
    };
    state.localItems = state.localItems.filter((i) => i.id !== item.id);
    state.localItems.push(item);
    saveLocalItems();
}

async function deleteItem() {
    if (!state.editing || !confirm(`Видалити «${state.editing.name}»?`)) {
        return;
    }
    if (state.editing.syncMode === 'LOCAL_ONLY') {
        state.localItems = state.localItems.filter((i) => i.id !== state.editing.id);
        saveLocalItems();
    } else {
        await api(`/api/vault/items/${state.editing.id}`, { method: 'DELETE' });
    }
    $('item-dialog').close();
    await refreshItems();
}

async function copyPassword() {
    const value = $('f-password').value;
    if (!value) {
        return;
    }
    await navigator.clipboard.writeText(value);
    if (state.editing && state.editing.syncMode !== 'LOCAL_ONLY') {
        api(`/api/vault/items/${state.editing.id}/copy-event`, { method: 'POST' }).catch(() => {});
    }
    const seconds = state.settings.clipboardClearSeconds;
    setTimeout(async () => {
        try {
            if ((await navigator.clipboard.readText()) === value) {
                await navigator.clipboard.writeText('');
            }
        } catch { /* clipboard read may be blocked; best effort */ }
    }, seconds * 1000);
    const btn = $('copy-pass');
    btn.textContent = `Copied (${seconds}s)`;
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
}

// --------------------------------------------------------------- sharing ---

async function renderPermissions() {
    const list = $('permission-list');
    list.innerHTML = '';
    const permissions = await api(`/api/vault/items/${state.editing.id}/permissions`);
    for (const permission of permissions) {
        const li = document.createElement('li');
        li.innerHTML = '<span></span><button type="button" class="secondary small">Revoke</button>';
        li.querySelector('span').textContent =
            `${permission.granteeType === 'GROUP' ? '👥' : '👤'} ${permission.grantee} — ${permission.role.toLowerCase()}`;
        li.querySelector('button').addEventListener('click', async () => {
            await api(`/api/vault/items/${state.editing.id}/permissions/${permission.id}`, { method: 'DELETE' });
            await renderPermissions();
        });
        list.appendChild(li);
    }
}

async function shareItem() {
    const grantee = $('share-grantee').value.trim();
    if (!grantee) {
        return;
    }
    try {
        await api(`/api/vault/items/${state.editing.id}/permissions`, {
            method: 'POST',
            body: JSON.stringify({
                granteeType: $('share-type').value,
                grantee,
                role: $('share-role').value,
            }),
        });
        $('share-grantee').value = '';
        $('dialog-error').hidden = true;
        state.editing.itemType = 'SHARED';
        $('f-type').value = 'SHARED';
        updateSyncControls();
        await renderPermissions();
    } catch (e) {
        showError($('dialog-error'), e.message);
    }
}

// ----------------------------------------------------------------- audit ---

async function loadAudit() {
    const body = $('audit-body');
    body.innerHTML = '';
    const events = await api('/api/audit?limit=200');
    for (const event of events) {
        const tr = document.createElement('tr');
        for (const value of [
            new Date(event.occurredAt).toLocaleString(),
            event.actorEmail,
            event.action,
            event.itemName || '',
            event.target || '',
            event.details || '',
        ]) {
            const td = document.createElement('td');
            td.textContent = value;
            tr.appendChild(td);
        }
        body.appendChild(tr);
    }
}

// -------------------------------------------------------------- settings ---

async function loadSettings() {
    state.settings = await api('/api/settings');
    $('setting-sync').value = state.settings.defaultSyncMode;
    $('setting-clipboard').value = state.settings.clipboardClearSeconds;
}

async function saveSettings() {
    state.settings = await api('/api/settings', {
        method: 'PUT',
        body: JSON.stringify({
            defaultSyncMode: $('setting-sync').value,
            clipboardClearSeconds: Number($('setting-clipboard').value) || 20,
        }),
    });
    $('settings-status').textContent = 'Збережено.';
    setTimeout(() => { $('settings-status').textContent = ''; }, 2000);
}

// ------------------------------------------------------------------ tabs ---

function switchTab(name) {
    for (const tab of document.querySelectorAll('.tab')) {
        tab.classList.toggle('active', tab.dataset.tab === name);
    }
    for (const panel of ['vault', 'audit', 'settings']) {
        $(`tab-${panel}`).hidden = panel !== name;
    }
    if (name === 'audit') {
        loadAudit().catch((e) => alert(e.message));
    }
}

// ------------------------------------------------------------------ init ---

$('unlock-btn').addEventListener('click', unlock);
$('passphrase').addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(); });
$('lock-btn').addEventListener('click', lock);
$('add-btn').addEventListener('click', openAddDialog);
$('search').addEventListener('input', renderItems);
$('item-form').addEventListener('submit', saveItem);
$('cancel-btn').addEventListener('click', () => $('item-dialog').close());
$('delete-btn').addEventListener('click', deleteItem);
$('copy-pass').addEventListener('click', copyPassword);
$('toggle-pass').addEventListener('click', () => {
    const field = $('f-password');
    field.type = field.type === 'password' ? 'text' : 'password';
});
$('f-type').addEventListener('change', updateSyncControls);
$('share-btn').addEventListener('click', shareItem);
$('save-settings-btn').addEventListener('click', () => saveSettings().catch((e) => alert(e.message)));
for (const tab of document.querySelectorAll('.tab')) {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
}
