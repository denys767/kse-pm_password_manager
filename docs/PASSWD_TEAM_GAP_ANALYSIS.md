# Зіставлення з passwd.team

## Уже є

- Keycloak/Google SSO, ролі та групи; WebAuthn налаштовується в Keycloak.
- Client-side AES-GCM, Argon2id для нових vault і per-item key wrapping.
- Personal/shared records, Collections, revoke, audit, history, генератор,
  HIBP k-anonymity і CSV import/export.
- Secret templates (`LOGIN`, API credentials, SSH key, card, secure note) і TOTP
  для LOGIN: усі template-specific значення, включно з seed, лише в encrypted
  payload; TOTP RFC 6238 обчислюється WebCrypto в браузері.

## Наступні пріоритети

1. ✅ Browser extension MVP та strict-origin autofill: Chrome MV3 popup працює з існуючим E2E vault, підтримує OIDC+PKCE, Argon2id/PBKDF2 unlock, пошук, fill і clipboard auto-clear. Залишаються auto-save, Firefox/Safari та enterprise deployment policy.
2. ✅ TOTP і secret templates (API credentials, SSH keys, cards, secure notes) — типізовані записи, TOTP RFC 6238 у браузері.
3. ✅ Локальний security dashboard: після unlock weak, reused, old (90+ днів) і breached secrets аналізуються локально; HIBP бачить лише 5-символьні SHA-1-префікси.
4. ✅ Керований lifecycle Google/Keycloak Groups: allowlist, read-only diff і явний E2E provisioning. Вступ до групи лише створює pending-запис без collection key; MANAGER обгортає ключ у браузері. Вихід блокує доступ і вимагає client-side ротації до остаточного revoke.
5. ✅ Timed external sharing: окремий AES-256 encrypted package, незалежний від permissions/collections. Ключ передається тільки у URL fragment і не надходить на сервер; V8 зберігає ciphertext+IV, TTL та one-time metadata. Public read rate-limited наявним `pm.rate-limit`, а create/view/expiry/revoke фіксуються в audit.
6. Mobile client та enterprise policies (IP allowlist, recovery/admin controls).

Цей пріоритетний список порівнює продукт з публічно описаними можливостями
passwd.team: templates, TOTP, temporary sharing, audit та browser extension.
Templates і TOTP вже закрито без зміни E2E boundary; наступні пункти лишаються
окремими етапами, а не частиною UX/redesign релізу.
