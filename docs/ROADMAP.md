# Roadmap: від MVP до повноцінного password manager

Статуси: ✅ виконано · 🔄 в роботі · ⬜ заплановано

## Фаза 1 — Security core ✅

Мета: закрити архітектурні діри безпеки, виявлені після MVP.

- ✅ **E2E per-item key wrapping** (модель Bitwarden): у кожного користувача RSA-OAEP-2048 keypair (приватний ключ зашифрований KEK з passphrase, зберігається на сервері — працює multi-device); у кожного запису власний AES-256 ключ, який зберігається лише обгорнутим публічним ключем кожного отримувача (`item_keys`). Отримувач share тепер реально розшифровує запис. Сервер ніколи не бачить незагорнутий ключ.
- ✅ **Flyway-міграції** (`db/migration/V1__baseline.sql`), `ddl-auto: validate` у проді.
- ✅ **Dev-guard**: профіль `dev` (header-автентифікація) не стартує без явного `PM_ALLOW_INSECURE_DEV=true`.
- Обмеження, що лишилось: прямий group-share (permission з `granteeType=GROUP`) видає лише метадані без wrapped key — член довільної групи бачить запис, але не може розшифрувати, доки owner не поділиться напряму. **Знято для командного use-case у Фазі 3 через Collections** (org-key, явне членство) — прямий group-share лишається як спосіб позначити намір, рекомендований шлях для реального спільного доступу тепер колекції.
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
- ✅ Онбординг: перший вхід автоматично генерує keypair (реалізовано у Фазі 1); коротка підказка про вибір passphrase на екрані Unlock.
- ✅ **Collections** (team/infrastructure з US-01, org-key модель): у колекції власний AES-256 ключ, обгорнутий RSA-публічним ключем кожного члена (`collections`/`collection_members`, V3-міграція); ключі записів колекції обгортаються ключем колекції (`password_items.collection_wrapped_key`). Ланцюжок розшифрування в браузері: приватний ключ → ключ колекції → item key → поля. Ролі MANAGER/EDITOR/VIEWER; MANAGER додає/видаляє членів і генерує wrapped-ключ для новачка (лише той, хто вже має ключ колекції, може його провізіонувати). Закриває головне обмеження Фази 1 — тепер group-sharing реально E2E, а не лише метадані. Перевірено Playwright-тестом (Alice створює колекцію → додає Bob EDITOR-ом → Bob розшифровує і редагує запис → після revoke доступу немає).
  - **Обмеження, зафіксовано свідомо:** ключ колекції не ротується при видаленні члена — видалений учасник, який встиг зберегти ключ локально, теоретично й далі розшифрує вже отриману ciphertext (ротація — наступний крок). Склад членів — явний (email + провізіонування ключа), синхронізація з Keycloak-групами через Admin API — окремий асистивний UX поверх цього ж механізму, не зроблено.

**Критерій готовності:** запис можна створити згенерованим паролем, поділитися колекцією на команду, відкотити до попередньої версії, імпортувати з CSV. **Досягнуто.**

## Фаза 4 — Production readiness 🔄

- ✅ OpenAPI-специфікація (springdoc): `/v3/api-docs` + Swagger UI (`/swagger-ui.html`) — контракт для мобільної апки (US-10). На публічному edge nginx блокує Swagger.
- ✅ CI: GitHub Actions — `mvn verify` (frontend + backend + тести) на кожен PR.
- ✅ Testcontainers-тест Flyway-міграцій проти справжнього PostgreSQL (CI-gated: `FlywayMigrationIT`, вмикається змінною `CI=true`).
- ✅ Dockerfile (multi-stage, non-root) + `docker-compose.prod.yml` з nginx: TLS termination, HSTS, CSP, X-Frame-Options; Postgres/Keycloak лише у внутрішній мережі; `/actuator/*` (крім health) закритий ззовні.
- ✅ Rate limiting: in-memory fixed window per client IP на `/api/**` (300 rpm за замовчуванням, `pm.rate-limit.requests-per-minute`); для горизонтального масштабування — bucket4j+Redis окремим кроком.
- ✅ Prometheus-метрики (`/actuator/prometheus`, micrometer).
- ✅ Dependabot (maven, npm, GitHub Actions, docker — щотижнево).
- ⬜ Keycloak event listener → audit LOGIN-подій.
- ⬜ Алерти на аномалії в audit (сплески share/revoke/copy); структуровані логи.
- ✅ Runbook бекапів/відновлення + чекліст перед запуском ([OPERATIONS.md](OPERATIONS.md)); сам процес бекапів налаштовується на хості за runbook-ом.

**Критерій готовності:** `docker compose -f docker-compose.prod.yml up` дає HTTPS-стек; CI зелений на кожен PR.

## Фаза 5 — Мобільна апка та розширення (майбутнє)

- ⬜ Мобільний клієнт поверх стабілізованого API (React Native), спільна crypto-логіка.
- ⬜ Browser extension для автозаповнення.
- ⬜ Argon2id замість PBKDF2 для KDF (коли WebCrypto/WASM-підтримка стане зручною).
