import { useEffect, useState } from 'react';
import { fetchConfig } from '../auth';
import { useI18n } from '../i18n';

/**
 * Landing page for the extension's OIDC sign-in tab.
 *
 * chrome.identity.launchWebAuthFlow ran the login in a stripped browser
 * context whose platform-WebAuthn support is unreliable; the extension now
 * opens this page in a normal tab instead (extension/src/background.ts,
 * launchSignInTab), so Keycloak's own passkey login works there like anywhere
 * else. This page's only job is to hand the authorization code back to the
 * extension over chrome.runtime.sendMessage — it never sees a token exchange,
 * and it deliberately never runs the web SPA's own OIDC bootstrap (App.tsx
 * intercepts this route before that), or this tab would also demand a login
 * for the kse-pm-web client it has nothing to do with.
 */
export function ExtensionCallbackPage() {
    const { language } = useI18n();
    const tr = (uk: string, en: string) => (language === 'uk' ? uk : en);
    const [status, setStatus] = useState(tr('Завершення входу…', 'Finishing sign-in…'));

    useEffect(() => {
        const params = new URLSearchParams(window.location.search);
        const code = params.get('code');
        const state = params.get('state');
        const error = params.get('error_description') ?? params.get('error') ?? undefined;
        void (async () => {
            if (typeof chrome === 'undefined' || !chrome.runtime?.sendMessage) {
                setStatus(tr('Ця сторінка призначена лише для розширення браузера.', 'This page is only meant to be opened by the browser extension.'));
                return;
            }
            try {
                const config = await fetchConfig();
                if (!config.extensionId) throw new Error('missing extensionId');
                await chrome.runtime.sendMessage(config.extensionId, { type: 'oidc-callback', code, state, error });
                setStatus(tr('Готово. Це вікно можна закрити.', 'Done. You can close this tab.'));
            } catch {
                setStatus(tr('Не вдалося передати результат розширенню.', 'Could not hand the result back to the extension.'));
            }
        })();
    }, []);

    return <div style={{ padding: 24 }}><p className="hint">{status}</p></div>;
}
