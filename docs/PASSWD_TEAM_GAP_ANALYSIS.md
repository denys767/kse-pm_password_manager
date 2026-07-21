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

1. Browser extension та autofill — найбільше щоденне UX-покращення.
2. ✅ TOTP і secret templates (API credentials, SSH keys, cards, secure notes) — типізовані записи, TOTP RFC 6238 у браузері.
3. ✅ Локальний security dashboard: після unlock weak, reused, old (90+ днів) і breached secrets аналізуються локально; HIBP бачить лише 5-символьні SHA-1-префікси.
4. Керований lifecycle Google Groups з явним E2E provisioning.
5. Timed external sharing; його потрібно проєктувати як окремий encrypted package.
6. Mobile client та enterprise policies (IP allowlist, recovery/admin controls).

Цей пріоритетний список порівнює продукт з публічно описаними можливостями
passwd.team: templates, TOTP, temporary sharing, audit та browser extension.
Templates і TOTP вже закрито без зміни E2E boundary; наступні пункти лишаються
окремими етапами, а не частиною UX/redesign релізу.
