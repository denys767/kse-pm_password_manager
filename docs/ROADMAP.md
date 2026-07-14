# Roadmap: від MVP до повноцінного password manager

Статуси: ✅ виконано · 🔄 в роботі · ⬜ заплановано

## Фаза 1 — Security core ✅

Мета: закрити архітектурні діри безпеки, виявлені після MVP.

- ✅ **E2E per-item key wrapping** (модель Bitwarden): у кожного користувача RSA-OAEP-2048 keypair (приватний ключ зашифрований KEK з passphrase, зберігається на сервері — працює multi-device); у кожного запису власний AES-256 ключ, який зберігається лише обгорнутим публічним ключем кожного отримувача (`item_keys`). Отримувач share тепер реально розшифровує запис. Сервер ніколи не бачить незагорнутий ключ.
- ✅ **Flyway-міграції** (`db/migration/V1__baseline.sql`), `ddl-auto: validate` у проді.
- ✅ **Dev-guard**: профіль `dev` (header-автентифікація) не стартує без явного `PM_ALLOW_INSECURE_DEV=true`.
- Обмеження, що лишилось: group-share видає лише permission-метадані без wrapped key — член групи бачить запис, але не може розшифрувати, доки owner не поділиться напряму. Повне рішення — колекції з org-key у Фазі 3.
- Відкладено: перевірка Flyway-міграцій проти реального PostgreSQL (Testcontainers) — додати разом з CI у Фазі 4.

**Критерій готовності:** отримувач share розшифровує запис своїм ключем (перевірено браузерним E2E-тестом); всі інтеграційні тести зелені.

## Фаза 2 — Frontend-платформа та справжня автентифікація 🔄

- ✅ Міграція на **React + TypeScript** (Vite, каталог `frontend/`); crypto-модуль перенесено як `crypto.ts` без зміни логіки; збірка інтегрована в Maven (frontend-maven-plugin → `static/`, `-Dfrontend.skip=true` для backend-ітерацій). Той самий Playwright E2E проходить проти React UI.
- ✅ **OIDC-флоу в коді**: `/api/config` повідомляє режим автентифікації; в oidc-режимі keycloak-js (Authorization Code + PKCE) з автооновленням токена і повним logout через end-session endpoint. Dev-режим лишається через X-Dev-* заголовки.
- ⬜ Прогнати OIDC-флоу проти живого Keycloak з Google IdP (потрібні реальні OAuth credentials).
- ⬜ **WebAuthn**: увімкнути в живому Keycloak за [KEYCLOAK.md](KEYCLOAK.md), UX-повідомлення про passkey, тест-матриця Chrome/Safari/Windows Hello (закриває Epic 7).

**Критерій готовності:** вхід через Keycloak (Google) → passkey → vault без dev-заголовків.

## Фаза 3 — Продуктові фічі 🔄

- ✅ Генератор паролів (CSPRNG, rejection sampling, гарантія всіх класів символів) + індикатор стійкості (ентропійна оцінка без залежностей; апгрейд до zxcvbn — окремим кроком).
- ✅ Перевірка компрометації через HaveIBeenPwned (k-anonymity: назовні йде лише 5-символьний префікс SHA-1, plaintext не покидає браузер).
- ✅ Історія версій запису (`password_item_versions`: ciphertext-снапшот перед кожним update, під тим самим item key) + відновлення у формі.
- ✅ Імпорт/експорт CSV (розшифрування/шифрування повністю на клієнті; кожен імпортований запис отримує власний item key). Формат Bitwarden — окремим кроком.
- ✅ Онбординг: перший вхід автоматично генерує keypair (реалізовано у Фазі 1).
- ⬜ **Collections** (team/infrastructure з US-01): org-key на колекцію, wrapped для кожного члена; склад членів — через Keycloak Admin API; закриває повноцінний group-sharing і знімає обмеження Фази 1.
- ⬜ Підказки по вибору passphrase та recovery-інструкції на екрані онбордингу.

**Критерій готовності:** запис можна створити згенерованим паролем, поділитися колекцією на команду, відкотити до попередньої версії, імпортувати з CSV.

## Фаза 4 — Production readiness (оцінка 1–2 тижні)

- ⬜ OpenAPI-специфікація (springdoc-openapi) — стабільний контракт для мобільної апки (US-10).
- ⬜ CI: GitHub Actions (build + test на PR), Dependabot.
- ⬜ Testcontainers-тест Flyway-міграцій проти справжнього PostgreSQL.
- ⬜ Dockerfile застосунку + prod docker-compose з nginx (TLS termination, security headers, CSP).
- ⬜ Rate limiting (bucket4j); Keycloak event listener → audit LOGIN-подій.
- ⬜ Prometheus-метрики, структуровані логи, алерти на аномалії в audit (сплески share/revoke/copy).
- ⬜ Бекапи PostgreSQL + runbook відновлення; чекліст security review перед запуском.

**Критерій готовності:** `docker compose -f docker-compose.prod.yml up` дає HTTPS-стек; CI зелений на кожен PR.

## Фаза 5 — Мобільна апка та розширення (майбутнє)

- ⬜ Мобільний клієнт поверх стабілізованого API (React Native), спільна crypto-логіка.
- ⬜ Browser extension для автозаповнення.
- ⬜ Argon2id замість PBKDF2 для KDF (коли WebCrypto/WASM-підтримка стане зручною).
