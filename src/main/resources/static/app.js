/*
 * KSE Password Manager — frontend shell (MVP, E2E key wrapping).
 *
 * Crypto model lives in crypto.js (PMCrypto): passphrase → KEK → decrypts the
 * user's RSA private key; every item has its own AES key, stored only wrapped
 * (RSA-OAEP per recipient on the server, KEK-wrapped for local-only items).
 * Plaintext secrets and unwrapped keys never leave the browser.
 *
 * Dev mode: identity is sent via X-Dev-User/X-Dev-Roles/X-Dev-Groups headers.
 * In production these headers are ignored — Keycloak issues a JWT instead.
 */

const state = {
    user: null,
    devHeaders: {},
    kek: null,          // AES key derived from the passphrase
    privateKey: null,   // own RSA private key (unwrapped, in memory only)
    publicKey: null,    // own RSA public key (CryptoKey, for wrapping at create)
    serverItems: [],
    localItems: [],
    settings: { defaultSyncMode: 'SERVER_SYNCED', clipboardClearSeconds: 20 },
    editing: null,      // item currently open in the dialog, null for "add" mode
    editingItemKey: null, // unwrapped AES key of the open item
};

const $ = (id) => document.getElementById(id);

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
        const error = new Error(message);
        error.status = response.status;
        throw error;
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

/**
 * First unlock generates the keypair and uploads it (private key encrypted
 * with the KEK); later unlocks download and decrypt it — a wrong passphrase
 * fails AES-GCM authentication and is reported cleanly. Works across devices
 * because the salt and encrypted private key live on the server.
 */
async function loadOrCreateKeys(passphrase) {
    let keys;
    try {
        keys = await api('/api/keys/me');
    } catch (e) {
        if (e.status !== 404) {
            throw e;
        }
        const salt = PMCrypto.generateSalt();
        const kek = await PMCrypto.deriveKek(passphrase, salt);
        const keypair = await PMCrypto.generateUserKeypair();
        const encPriv = await PMCrypto.exportEncryptedPrivateKey(keypair.privateKey, kek);
        const publicKeyB64 = await PMCrypto.exportPublicKey(keypair.publicKey);
        await api('/api/keys/me', {
            method: 'PUT',
            body: JSON.stringify({
                publicKey: publicKeyB64,
                encryptedPrivateKey: encPriv.ct,
                privateKeyIv: encPriv.iv,
                kdfSalt: salt,
            }),
        });
        state.kek = kek;
        state.privateKey = keypair.privateKey;
        state.publicKey = await PMCrypto.importPublicKey(publicKeyB64);
        return;
    }
    const kek = await PMCrypto.deriveKek(passphrase, keys.kdfSalt);
    try {
        state.privateKey = await PMCrypto.importEncryptedPrivateKey(
            keys.encryptedPrivateKey, keys.privateKeyIv, kek);
    } catch {
        throw new Error('Невірний passphrase для цього vault.');
    }
    state.kek = kek;
    state.publicKey = await PMCrypto.importPublicKey(keys.publicKey);
}

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
        await loadOrCreateKeys(passphrase);
    } catch (e) {
        return showError(errorEl, e.message.startsWith('Невірний') ? e.message
            : `Не вдалося увійти: ${e.message}`);
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
    state.kek = null;
    state.privateKey = null;
    state.publicKey = null;
    state.user = null;
    state.serverItems = [];
    state.localItems = [];
    state.editingItemKey = null;
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
        li.addEventListener('click', () => openItem(item).catch((e) => alert(e.message)));
        list.appendChild(li);
    }
}

/** Unwrap the AES key of an item: RSA for server items, KEK for local-only. */
async function itemKeyOf(item) {
    if (item.syncMode === 'LOCAL_ONLY') {
        return PMCrypto.unwrapItemKeyWithKek(item.kekWrappedKey.ct, item.kekWrappedKey.iv, state.kek);
    }
    if (!item.wrappedKey) {
        throw new Error('Для вас ще не надано ключ до цього запису '
            + '(group-share без ключа — попросіть owner-а поділитися напряму).');
    }
    return PMCrypto.unwrapItemKey(item.wrappedKey, state.privateKey);
}

async function openItem(listItem) {
    let item = listItem;
    if (item.syncMode !== 'LOCAL_ONLY') {
        // Server GET also records the ITEM_VIEWED audit event.
        item = await api(`/api/vault/items/${item.id}`);
    }
    state.editing = item;
    state.editingItemKey = null;
    $('dialog-title').textContent = item.name;
    $('f-name').value = item.name;
    $('f-url').value = item.url || '';
    $('f-username').value = item.username || '';
    $('f-password').type = 'password';
    $('dialog-error').hidden = true;
    try {
        const itemKey = await itemKeyOf(item);
        state.editingItemKey = itemKey;
        $('f-password').value = await PMCrypto.decryptField(itemKey, item.encryptedPassword, item.passwordIv);
        $('f-notes').value = item.encryptedNotes
            ? await PMCrypto.decryptField(itemKey, item.encryptedNotes, item.notesIv)
            : '';
    } catch (e) {
        $('f-password').value = '';
        $('f-notes').value = '';
        showError($('dialog-error'), e.message.startsWith('Для вас')
            ? e.message
            : 'Не вдалося розшифрувати запис (ключ не підходить).');
    }
    $('f-tags').value = item.tags || '';
    $('f-type').value = item.itemType;
    $('f-sync').checked = item.syncMode !== 'LOCAL_ONLY';

    const isOwner = !item.accessRole || item.accessRole === 'OWNER';
    const canEdit = (isOwner || item.accessRole === 'EDITOR') && state.editingItemKey !== null;
    for (const id of ['f-name', 'f-url', 'f-username', 'f-password', 'f-notes', 'f-tags']) {
        $(id).readOnly = !canEdit;
    }
    $('f-type').disabled = !isOwner;
    $('save-btn').hidden = !canEdit;
    $('delete-btn').hidden = !isOwner;
    $('copy-pass').hidden = state.editingItemKey === null;
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
    state.editingItemKey = null;
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
        // Existing item keeps its key (recipients keep access); new item gets a fresh one.
        const itemKey = state.editingItemKey || await PMCrypto.generateItemKey();
        const password = await PMCrypto.encryptField(itemKey, $('f-password').value);
        const notes = $('f-notes').value
            ? await PMCrypto.encryptField(itemKey, $('f-notes').value)
            : null;
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
            await saveSynced(payload, itemKey, wasLocal);
        } else {
            await saveLocalOnly(payload, itemKey);
        }
        $('item-dialog').close();
        await refreshItems();
    } catch (e) {
        showError(errorEl, e.message);
    }
}

async function saveSynced(payload, itemKey, wasLocal) {
    if (state.editing && !wasLocal) {
        await api(`/api/vault/items/${state.editing.id}`, { method: 'PUT', body: JSON.stringify(payload) });
        return;
    }
    payload.wrappedKey = await PMCrypto.wrapItemKey(itemKey, state.publicKey);
    await api('/api/vault/items', { method: 'POST', body: JSON.stringify(payload) });
    if (state.editing && wasLocal) {
        state.localItems = state.localItems.filter((i) => i.id !== state.editing.id);
        saveLocalItems();
    }
}

async function saveLocalOnly(payload, itemKey) {
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
        kekWrappedKey: await PMCrypto.wrapItemKeyWithKek(itemKey, state.kek),
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
    const grantee = $('share-grantee').value.trim().toLowerCase();
    if (!grantee) {
        return;
    }
    const granteeType = $('share-type').value;
    try {
        const body = {
            granteeType,
            grantee,
            role: $('share-role').value,
        };
        if (granteeType === 'USER') {
            if (!state.editingItemKey) {
                throw new Error('Немає ключа запису — розшифруйте запис перед шерингом.');
            }
            let recipient;
            try {
                recipient = await api(`/api/keys/${encodeURIComponent(grantee)}`);
            } catch (e) {
                throw e.status === 404
                    ? new Error(`У ${grantee} ще немає ключів — користувач має увійти у vault хоча б раз.`)
                    : e;
            }
            const recipientKey = await PMCrypto.importPublicKey(recipient.publicKey);
            body.wrappedKey = await PMCrypto.wrapItemKey(state.editingItemKey, recipientKey);
        }
        const created = await api(`/api/vault/items/${state.editing.id}/permissions`, {
            method: 'POST',
            body: JSON.stringify(body),
        });
        $('share-grantee').value = '';
        $('dialog-error').hidden = true;
        if (created.warning) {
            showError($('dialog-error'), `⚠ ${created.warning}`);
        }
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
