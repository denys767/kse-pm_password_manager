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
- ✅ **OIDC-флоу в коді й live Keycloak**: `/api/config` повідомляє режим автентифікації; в oidc-режимі keycloak-js (Authorization Code + PKCE) з автооновленням токена і повним logout через end-session endpoint. Live-прогін з локальним користувачем підтвердив PKCE-redirect, реальний JWT у `/api/me` (email, realm roles і groups) та завершення SSO-сесії через logout. Dev-режим лишається через X-Dev-* заголовки.
- ⬜ Прогнати OIDC-флоу саме з Google IdP (потрібні реальні Google OAuth credentials).
- 🔄 **WebAuthn**: `browser-webauthn` flow і default required action налаштовано в живому Keycloak; реєстрація passkey пройшла в Chromium з CDP virtual authenticator. ⬜ Повторна assertion/login тим самим credential, а також ручна матриця Chrome/Safari/Windows Hello/Touch ID ще потребують перевірки (закриває Epic 7).

**Критерій готовності:** вхід через Keycloak (Google) → passkey → vault без dev-заголовків.

## Фаза 3 — Продуктові фічі 🔄

- ✅ Генератор паролів (CSPRNG, rejection sampling, гарантія всіх класів символів) + індикатор стійкості (ентропійна оцінка без залежностей; апгрейд до zxcvbn — окремим кроком).
- ✅ Перевірка компрометації через HaveIBeenPwned (k-anonymity: назовні йде лише 5-символьний префікс SHA-1, plaintext не покидає браузер).
- ✅ Історія версій запису (`password_item_versions`: ciphertext-снапшот перед кожним update, під тим самим item key) + відновлення у формі.
- ✅ Імпорт/експорт CSV (розшифрування/шифрування повністю на клієнті; кожен імпортований запис отримує власний item key). Формат Bitwarden — окремим кроком.
- ✅ Онбординг: перший вхід автоматично генерує keypair (реалізовано у Фазі 1); коротка підказка про вибір passphrase на екрані Unlock.
- ✅ **Collections** (team/infrastructure з US-01, org-key модель): у колекції власний AES-256 ключ, обгорнутий RSA-публічним ключем кожного члена (`collections`/`collection_members`, V3-міграція); ключі записів колекції обгортаються ключем колекції (`password_items.collection_wrapped_key`). Ланцюжок розшифрування в браузері: приватний ключ → ключ колекції → item key → поля. Ролі MANAGER/EDITOR/VIEWER; MANAGER додає/видаляє членів і генерує wrapped-ключ для новачка (лише той, хто вже має ключ колекції, може його провізіонувати). Закриває головне обмеження Фази 1 — тепер group-sharing реально E2E, а не лише метадані. Перевірено Playwright-тестом (Alice створює колекцію → додає Bob EDITOR-ом → Bob розшифровує і редагує запис → після revoke доступу немає).
  - **Ротація ключа при revoke ✅:** і прямий share (`SharingService.revoke`), і видалення члена колекції (`CollectionService.removeMember`) тепер супроводжуються ротацією AES-ключа — новий `POST /api/vault/items/{id}/rotate-key` (для прямого share: власник перешифровує password/notes новим item key і перегортає його для owner + кожного отримувача, що лишається) і `POST /api/collections/{id}/rotate-key` (для колекцій: новий collection key перегортається для членів, що лишаються, і для item key кожного запису колекції). Той, кого відкликають, більше не отримує новий wrapped key, тому не може розшифрувати жодні майбутні зміни запису. Ротація для прямого share пропускається, якщо запис належить колекції (там ключ колекції окремий) — керується через `PasswordItem.collectionId`-guard на backend.
  - **Обмеження, що лишається (властивість crypto-shredding, не баг):** ротація захищає майбутні зміни й майбутні читання через API, але не є захистом від пристрою, що вже мав дані в момент компрометації — якщо відкликаний користувач встиг завантажити ciphertext до ротації, стару копію (яку він уже отримав) він і далі розшифрує старим ключем. Склад членів колекції — явний (email + провізіонування ключа), синхронізація з Keycloak-групами через Admin API — окремий асистивний UX поверх цього ж механізму, не зроблено.
  - ✅ **Keycloak group suggestions (Admin API):** optional `keycloak_group` зберігається на колекції. MANAGER може отримати diff email-ів обраної Keycloak-групи через read-only service account `kse-pm-admin` (`realm-management:view-users`) і явно відмітити їх у UI. Кожен вибраний користувач все одно отримує collection key лише після client-side RSA wrapping — Keycloak-група не дає автоматичного криптографічного доступу. `KeycloakAdminClient` має детермінований HTTP-тест token → group search → members, включно з 401, відсутньою й порожньою групою. **✅ Live:** Keycloak 26 `dev-team` повернув diff `[bob-live@kse.org.ua]`; Playwright додав його через явний wrapping, після чого Bob побачив колекцію.

**Критерій готовності:** запис можна створити згенерованим паролем, поділитися колекцією на команду, відкотити до попередньої версії, імпортувати з CSV. **Досягнуто.**

## Фаза 4 — Production readiness 🔄

- ✅ OpenAPI-специфікація (springdoc): `/v3/api-docs` + Swagger UI (`/swagger-ui.html`) — контракт для мобільної апки (US-10). На публічному edge nginx блокує Swagger.
- ✅ CI: GitHub Actions — `mvn verify` (frontend + backend + тести) на кожен PR.
- ✅ Testcontainers-тест Flyway-міграцій проти справжнього PostgreSQL (CI-gated: `FlywayMigrationIT`, вмикається змінною `CI=true`).
- ✅ Dockerfile (multi-stage, non-root) + `docker-compose.prod.yml` з nginx: TLS termination, HSTS, CSP, X-Frame-Options; Postgres/Keycloak лише у внутрішній мережі; `/actuator/*` (крім health) закритий ззовні.
- ✅ Rate limiting: in-memory fixed window per client IP на `/api/**` (300 rpm за замовчуванням, `pm.rate-limit.requests-per-minute`); для горизонтального масштабування — bucket4j+Redis окремим кроком.
- ✅ Prometheus-метрики (`/actuator/prometheus`, micrometer).
- ✅ Dependabot (maven, npm, GitHub Actions, docker — щотижнево).
- ✅ **Keycloak event ingestion → audit LOGIN-подій:** internal `POST /api/audit/keycloak-events` приймає `LOGIN`, `LOGIN_ERROR`, `LOGOUT` від event-listener provider-а, автентифікує запит constant-time shared secret-ом `X-Keycloak-Events-Secret` (`KEYCLOAK_EVENTS_SECRET`) і зберігає `LOGIN`/`LOGIN_FAILED`/`LOGOUT`. Публічний nginx повертає 404 для цього маршруту; listener має звертатися прямо до `app:8080` внутрішньою Docker-мережею. `LOGIN_FAILED` має поріг 5/15 хв для brute-force anomaly. MockMvc-тести покривають секрет, мапінг і anomaly.
  - **✅ Live endpoint і anomaly:** реальні `curl`-доставки з валідним shared secret записали LOGIN/LOGOUT/LOGIN_FAILED, а шість LOGIN_FAILED показали brute-force banner в Playwright UI; невалідний secret отримав 403. **⬜ Автоматичну доставку саме з Keycloak ще не підтверджено:** Keycloak 26.0 не має вбудованого HTTP/webhook Event Listener; потрібен перевірений сторонній HTTP listener provider або власний EventListener SPI (інструкція в [KEYCLOAK.md](KEYCLOAK.md)).
- ✅ **Алерти на аномалії в audit** (сплески share/revoke/copy): порогова евристика `AuditAnomalyService` — для кожної пари (актор, тип дії) рахує кількість подій за останні `pm.audit.anomaly.window-minutes` (за замовчуванням 15 хв) і порівнює з порогом (ACCESS_REVOKED/COLLECTION_MEMBER_REMOVED = 5, ITEM_COPIED/ITEM_SHARED = 10, інше = 20). Обчислюється на вимогу при виклику `GET /api/audit/anomalies` (той самий доступ, що й `/api/audit` — admin/security), без scheduler. Frontend показує червоний банер над таблицею audit log. Перевірено: MockMvc-тести (сплеск флагується, легка активність — ні, non-admin отримує 403) + живий curl-прогін + Playwright (банер рендериться з реальними даними).
  - **Обмеження, зафіксовано свідомо:** це прості пороги, не ML/SIEM — не ловить повільні, розподілені в часі атаки чи змову кількох акаунтів. Для продакшена варто інтегрувати з реальним security-моніторингом (напр. експорт у SIEM через Prometheus-метрики, які вже є).
- ✅ **Структуровані логи**: ECS (Elastic Common Schema) JSON на stdout поза `dev`-профілем — вбудована можливість Spring Boot 3.4 (`logging.structured.format.console: ecs`), без додаткових залежностей. `LoggingContextFilter` (виконується після Spring Security filter chain) додає `actorEmail`/`requestId` в MDC на час запиту — кореляція технічних логів із конкретним користувачем/запитом, доповнює `audit_events`. `dev`-профіль лишається людино-читним. Перевірено: тест з Logback `ListAppender` (MDC заповнюється й коректно чиститься після запиту, не витікає між запитами) + живий прогін обох профілів (`dev` → plain text, звичайний профіль → валідний ECS JSON, перевірено `python3 json.loads` на кожному рядку).
- ✅ Runbook бекапів/відновлення + чекліст перед запуском ([OPERATIONS.md](OPERATIONS.md)); сам процес бекапів налаштовується на хості за runbook-ом.

**Критерій готовності:** `docker compose -f docker-compose.prod.yml up` дає HTTPS-стек; CI зелений на кожен PR.

## Фаза 5 — Мобільна апка та розширення 🔄

- ⬜ Мобільний клієнт поверх стабілізованого API (React Native), спільна crypto-логіка.
- ✅ **Browser extension MVP (T4):** ізольований `extension/` Chrome Manifest V3 клієнт: OIDC Authorization Code + PKCE через `chrome.identity`, unlock існуючого vault з Argon2id або legacy PBKDF2 і тим самим KEK → RSA → collection/item-key ланцюжком, strict origin autofill, пошук та copy з автоочищенням. Ключі й токен існують лише в пам'яті service worker; сервер отримує тільки ciphertext/wrapped keys. Auto-save поза scope. Keycloak redirect URI налаштовується окремим public client-ом на конкретний `https://<extension-id>.chromiumapp.org/oidc`, без wildcard.
- ⬜ TOTP, secret templates та локальний security dashboard (див. `PASSWD_TEAM_GAP_ANALYSIS.md`).
- ✅ **Argon2id замість PBKDF2 для KDF**: нові keypair-и виводять KEK через Argon2id (`hash-wasm`, memory-hard, m=19 MiB/t=2/p=1 — OWASP-рекомендація для constrained/browser середовищ), значно дорожче брутфорсити на GPU/ASIC за той самий wall-clock час unlock, ніж PBKDF2. **Версіонується**: `UserKeys.kdfAlgorithm` (`PBKDF2`/`ARGON2ID`, Flyway V4) — існуючі keypair-и й далі розшифровуються тим алгоритмом, яким були зареєстровані (немає примусової міграції: перевивести KEK можна лише з passphrase користувача, якого сервер не має). Перевірено: backend-тест (обов'язковість поля, збереження/зчитування обох значень), Playwright E2E (unlock ~1с, коректне відхилення невірного passphrase, повний ланцюжок share/decrypt між двома новими ARGON2ID-користувачами), регресія прямого share.
