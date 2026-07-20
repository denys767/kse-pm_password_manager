# Зіставлення з passwd.team

## Уже є

- Keycloak/Google SSO, ролі та групи; WebAuthn налаштовується в Keycloak.
- Client-side AES-GCM, Argon2id для нових vault і per-item key wrapping.
- Personal/shared records, Collections, revoke, audit, history, генератор,
  HIBP k-anonymity і CSV import/export.

## Наступні пріоритети

1. Browser extension та autofill — найбільше щоденне UX-покращення.
2. TOTP і secret templates (API credentials, SSH keys, cards, secure notes).
3. Локальний security dashboard: weak, reused, old і breached secrets.
4. Керований lifecycle Google Groups з явним E2E provisioning.
5. Timed external sharing; його потрібно проєктувати як окремий encrypted package.
6. Mobile client та enterprise policies (IP allowlist, recovery/admin controls).

Цей пріоритетний список порівнює продукт з публічно описаними можливостями
passwd.team: templates, TOTP, temporary sharing, audit та browser extension.
Поточна версія навмисно не додає ці можливості разом із UX/redesign релізом.
