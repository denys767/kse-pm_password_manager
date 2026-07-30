# Архітектура KSE Password Manager

Цей документ описує фактичну архітектуру застосунку: вебклієнт і Chrome-розширення, backend, ідентифікацію, криптографію, дані, інтеграції та розгортання. Він доповнює експлуатаційні інструкції в [OPERATIONS.md](OPERATIONS.md), налаштування SSO в [KEYCLOAK.md](KEYCLOAK.md) і процес деплою в [DEPLOYMENT.md](DEPLOYMENT.md).

## 1. Призначення та ключові межі

KSE Password Manager — корпоративний менеджер паролів. Він централізує облік доступів, спільний доступ, аудит і керування користувачами Google Workspace, але **не є довіреною стороною для plaintext-секретів**:

- пароль, нотатки, TOTP-секрети, приватні ключі та вкладення шифруються на пристрої користувача;
- сервер зберігає ciphertext, метадані, загорнуті ключі, правила доступу та аудит;
- Keycloak встановлює особу користувача, а локальний знімок Google Workspace визначає, чи має ця особа доступ і яку корпоративну роль вона має;
- розширення браузера — окремий OAuth-клієнт, якому доступний спеціальний матеріал для WebAuthn/passkey. Звичайна веб-SPA його не отримує.

Відкритими навмисно лишаються метадані, потрібні для UX і контролю доступу: назва запису, URL, username, теги, власник, часові мітки, склад колекцій та аудит. Це важливе обмеження моделі приватності.

## 2. Карта системи

```text
                         ┌──────────────────────── Google Workspace ────────────────────────┐
                         │ Google SSO / Directory API / Drive appDataFolder                  │
                         └───────▲──────────────────▲──────────────────────────▲────────────┘
                                 │                  │                          │
                         identity broker      governed snapshot          encrypted attachments
                                 │                  │                          │
Browser ──── HTTPS ───► nginx ───┼──► Keycloak ─────┘                          │
  │                         │    │  (Google IdP, realm, passkey login)           │
  │                         │    │                                               │
  │                         │    └──► Spring Boot REST API ──────────────────────┘
  │                         │             │             │
  │                         │             │             └── OAuth2 JWT validation, governance,
  │                         │             │                 authorization, rate limiting, audit
  │                         │             ▼
  │                         │        PostgreSQL 16
  │                         │        ciphertext, wrapped keys, metadata, policy, audit
  │                         │
  ├── React SPA + WebCrypto / hash-wasm
  └── Chrome Extension (MV3): popup, service worker, content script, offscreen document
```

У production `nginx` є єдиною публічною точкою входу: застосунок доступний через `:443`, Keycloak — через `:8443`. PostgreSQL, Spring Boot і Keycloak спілкуються внутрішньою Docker-мережею. У development можна запускати backend з H2 та профілем `dev`, без Keycloak — лише за явного `PM_ALLOW_INSECURE_DEV=true`.

## 3. Компоненти та відповідальність

| Частина | Технології | Відповідальність | Не робить |
|---|---|---|---|
| Вебклієнт | React 18, TypeScript, Vite, WebCrypto, `hash-wasm`, `keycloak-js` | UI, OIDC-сесія, локальне/клієнтське шифрування, криптографічні операції для sharing | Не передає passphrase або розгорнуті item keys на сервер |
| Chrome extension | Manifest V3, TypeScript, WebCrypto, offscreen document | Autofill, генерація/збереження паролів, TOTP, passkeys, ізольована сесія vault | Не показує сайтам сам vault або повні записи без вибору користувача |
| API | Spring Boot 3.4, Java 21, Spring Security, JPA | REST API, перевірка JWT, бізнес-правила, авторизація, аудит, стримінг вкладень | Не розшифровує vault-дані |
| Сховище | PostgreSQL 16, Flyway | Довговічний стан і транзакції | Не зберігає raw item keys або plaintext-секрети |
| Identity | Keycloak 26 + Google Workspace IdP | SSO, OAuth2/OIDC токени, WebAuthn required action, realm-конфігурація | Не є джерелом корпоративних ролей API |
| Google інтеграції | Admin SDK Directory API, Drive API, Google STS/IAM | Знімок користувачів/груп; encrypted attachments у per-user Drive; keyless credentials | Не надають групі криптографічний доступ автоматично |
| Edge та observability | nginx, Actuator, Prometheus, ECS JSON logs | TLS, security headers, route isolation, health/metrics | Не замінює авторизацію в backend |

## 4. Вебклієнт і розширення

### Веб SPA

`frontend/` збирається Vite. Maven запускає її збірку в `generate-resources`, а `maven-resources-plugin` копіює `frontend/dist` у static-ресурси backend. Тому один Spring Boot artifact віддає SPA та API. Для швидкої backend-ітерації доступний `-Dfrontend.skip=true`; для окремого UI-запуску Vite проксіює API на `:8080`.

Ключові frontend-модулі:

- `auth.ts` — ініціалізація Keycloak/OIDC, dev identity, завантаження й розблокування keypair;
- `crypto.ts`, `itemKeys.ts`, `webauthnVault.ts` — WebCrypto, key wrapping, vault unlock через WebAuthn;
- `api.ts` — типізований клієнт REST;
- `VaultTab`, `CollectionsTab`, `AuditTab`, `AdminTab`, `SettingsTab`, `DashboardTab`, `TagsTab` — функціональні екрани;
- `ExternalSharePage` — розшифровує public package у браузері; ключ береться з URL fragment, який не відправляється серверу;
- `extensionBridge.ts` та `ExtensionCallbackPage` — безпечна координація SPA й extension.

### Chrome extension

`extension/` — окремий дистрибутив. Його service worker тримає короткоживучу unlock-сесію; popup керує станом, content script працює лише з полями поточної сторінки, а offscreen document потрібний для операцій, що не можна безпечно виконати у worker.

Розширення:

- підбирає записи за точним origin і заповнює username/password лише після вибору;
- пропонує згенерований пароль на signup-формах та зберігає нові облікові дані після submit;
- обчислює TOTP, може прочитати `otpauth://` із QR на сторінці;
- реалізує WebAuthn proxy для passkey-записів;
- має `webAuthenticationProxy`, але endpoint-и `/api/passkeys/**` додатково перевіряють OAuth client ID та audience `kse-pm-extension`.

Content script не отримує весь vault: він надсилає `itemId` до background worker; сам worker віддає сайту лише потрібне поле. Коли vault заблокований, picker не розкриває username записів.

## 5. Автентифікація, governance та авторизація

### Потік входу

```text
1. SPA/extension → Keycloak
2. Keycloak → Google Workspace SSO → Keycloak
3. Для нового акаунта Keycloak вимагає реєстрацію passkey
4. Keycloak → клієнт: OIDC access token (JWT)
5. Клієнт → API: Authorization: Bearer <JWT>
6. Spring перевіряє підпис та issuer JWT
7. GovernedAuthenticationFilter знаходить email у локальному Workspace snapshot
8. API замінює claims токена однією ефективною локальною роллю і виконує endpoint
```

Ролі в JWT свідомо не є джерелом прав API. `GovernedAuthenticationFilter` після JWT lookup-ає `workspace_users`: заблокований, видалений або не provisioned користувач отримує `403`. До першої успішної синхронізації застосунок за замовчуванням fail-closed. Опція `PM_GOOGLE_WORKSPACE_PROVISIONAL_ACCESS=true` дозволяє лише in-domain користувачам тимчасовий `USER`-доступ на порожньому snapshot — це компроміс доступності, не нормальний режим.

У `dev` профілі `X-Dev-User`, `X-Dev-Roles`, `X-Dev-Groups` створюють тестову identity. Ці заголовки неприйнятні поза локальною розробкою; `DevProfileGuard` не дає випадково запустити dev без явного opt-in.

### Рівні доступу

| Рівень | Значення | Джерело |
|---|---|---|
| Корпоративний | `USER`, `ADMIN`, `SECURITY` | `workspace_users.role_override`, після Directory sync |
| Запис | implicit `OWNER`, `EDITOR`, `VIEWER`, `PASSKEY_ONLY` | `password_items` + `permissions` + активні `permission_members` |
| Колекція | `MANAGER`, `EDITOR`, `VIEWER` | `collection_members` |

`ADMIN` і `SECURITY` читають audit, керують Workspace і тегами, але не отримують автоматичного права розшифрувати чужий vault. Owner керує записом; editor змінює вміст; viewer читає; manager колекції ще й керує її складом. Обмежений `PASSKEY_ONLY` доступ може дати extension криптографічний матеріал для passkey, не відкриваючи raw password вебклієнту.

## 6. E2E-криптографія та життєвий цикл ключів

### Ключі користувача і запису

1. Passphrase ніколи не залишає браузер.
2. Клієнт виводить KEK: нові keypair-и — Argon2id (`m=19 MiB`, `t=2`, `p=1`); legacy keypair-и — PBKDF2-SHA-256, 210 000 ітерацій. `user_keys.kdf_algorithm` дозволяє обом схемам співіснувати.
3. Браузер генерує RSA-OAEP-2048 keypair. Публічний ключ зберігається як SPKI; приватний PKCS8 шифрується KEK AES-GCM і зберігається разом із salt та IV.
4. Для кожного запису генерується AES-256 item key. `encrypted_password` і `encrypted_notes` шифруються AES-GCM з окремими IV.
5. Item key зберігається лише як RSA-OAEP envelope у `item_keys` — по одному для кожного користувача, який має доступ.

Прямий share відбувається у клієнті owner: item key розгортається його приватним ключем, загортається публічним ключем отримувача і передається разом із permission. Backend перевіряє політику та зберігає результат, але не бачить raw key.

### Колекції

Колекція має AES-256 collection key. Він RSA-загорнутий для кожного учасника (`collection_members.wrapped_key`). Item key запису у колекції загортається collection key через AES-GCM (`collection_wrapped_key`), тому додавання члена створює лише один новий RSA envelope — перешифровувати всі записи не потрібно.

Ланцюжок розшифрування: приватний ключ користувача → collection key → item key → ciphertext полів. Google group використовується як підказка та матеріалізований список кандидатів; її членство **не створює** криптографічний доступ само по собі. Manager явно затверджує членів і браузер створює envelope для кожного.

### Відкликання і відновлення

Перед revoke клієнт owner/manager виконує ротацію ключа: генерує новий item/collection key, повторно шифрує дані або envelope-и для тих, хто лишається, потім прибирає доступ. Це crypto-shredding для майбутніх API-чтень, але не може стерти ciphertext, уже скопійований на скомпрометований пристрій.

Для керованого відновлення існують `recovery_key_envelopes`, `recovery_operations` і `user_notifications`: KMS ciphertext містить лише recovery envelope, не raw key. Recovery API показує impact, переносить ownership або скидає vault за контрольованою операцією та створює аудит/сповіщення.

### Інші encrypted payload-и

- **Local-only**: запис не синхронізується; його key загорнутий KEK і разом із ciphertext лежить у browser localStorage. Shared item не може бути local-only.
- **Зовнішній share**: browser формує encrypted package, server зберігає opaque blob із expiry/one-time policy. AES key міститься лише після `#` у share URL, тож не потрапляє до HTTP-запиту, логів чи БД.
- **Вкладення**: browser шифрує файл власним file key, metadata (назва, nonce, wrapped file key, SHA-256, розмір) зберігається в PostgreSQL, opaque bytes — у Drive.
- **Passkey credential**: public credential і encrypted private material зберігаються у `passkey_credentials`; envelope-и спільного доступу — у `passkey_credential_keys`.

## 7. Backend: модулі та дані

Код backend розділено за доменами, а контролери є тонким HTTP-шаром над сервісами, репозиторіями JPA та DTO. Винятки нормалізує `common/ApiExceptionHandler`.

| Пакет | Відповідальність | Основні дані |
|---|---|---|
| `auth` | Resource server, dev security, governance filter, rate limit, request context, `/api/me`, `/api/config` | identity у SecurityContext |
| `vault` | CRUD, версії, імпорт CSV, sync mode, key rotation, перенесення/скидання ownership, tags | `password_items`, `item_keys`, `password_item_versions` |
| `keys` | Реєстрація та пошук public keys | `user_keys` |
| `sharing` | User/group permissions, materialized group members, provision/sync/revoke | `permissions`, `permission_members` |
| `collections` | Колекції, ролі, group suggestions/sync, collection key rotation | `collections`, `collection_members`, `allowed_keycloak_groups` |
| `directory` | Workspace snapshot, scheduled/manual refresh, статус credentials, admin overrides | `workspace_users`, `workspace_groups`, `workspace_group_memberships` |
| `attachment` | Перевірка owner/read access, stream upload/download, Drive cleanup/transfer | `item_attachments` + Drive files |
| `externalsharing` | Створення, читання, expiry, one-time та revoke public packages | `external_shares` |
| `passkeys` | Extension-only credential CRUD, sign counter, wrapped-key distribution | `passkey_credentials`, `passkey_credential_keys` |
| `audit` | Business events, paged filters, anomaly detection, Keycloak ingest | `audit_events` |
| `google` | Caller credentials, federated token, domain-wide delegated token minting | без власного persistent стану |

### PostgreSQL і міграції

Flyway застосовує `V1`–`V23` на PostgreSQL; Hibernate працює з `ddl-auto=validate`, а не створює схему. Основні групи таблиць:

- **Vault**: `password_items`, `item_keys`, `password_item_versions`, `user_keys`, `user_settings`, `item_attachments`.
- **Доступ**: `permissions`, `permission_members`, `collections`, `collection_members`, `allowed_keycloak_groups`.
- **Governance**: `workspace_users`, `workspace_groups`, `workspace_group_memberships`.
- **Додаткові можливості**: `external_shares`, `passkey_credentials`, `passkey_credential_keys`, recovery-таблиці, `audit_events`.

Foreign keys каскадно прибирають похідний стан (наприклад, keys, versions, external shares і passkeys записи при видаленні item). Індекси підтримують owner/item lookup, membership, audit filters та paged chronological audit.

## 8. Google Workspace і Drive

`WorkspaceDirectorySyncService` отримує users, groups та memberships через `WorkspaceDirectoryClient`, записує локальний snapshot та запускається за розкладом; `ADMIN` може примусово оновити його через `/api/admin/workspace/refresh`. Snapshot — авторизаційна межа, тому синхронізація має бути атомарною: scheduled reconciler викликає транзакційну операцію через Spring proxy, щоб падіння в середині не залишало частково застосований стан.

У production Directory API отримує domain-wide delegated token. Переважний ланцюжок credentials: workload identity federation (Keycloak client_credentials → Google STS) або attached service account; service-account JSON key — останній fallback. Людський `gcloud auth application-default login` не придатний для production через повторну Google re-authentication.

Вкладення йдуть до приватного `appDataFolder` owner у Google Drive. Upload/download стрімляться без буферизації всього файла в heap і без довгої DB-транзакції: сервіс робить короткий read transaction, Drive transfer, короткий write transaction. При заміні старий Drive object прибирається тільки після успішного запису нового. При transfer ownership файл перевіряється SHA-256, переноситься до Drive нового owner, потім оновлюється metadata та видаляється стара копія.

## 9. REST API за доменами

Усі endpoint-и нижче, крім явно public/internal, вимагають JWT та проходять governance filter. OpenAPI доступна у dev/staging за `/swagger-ui.html`.

| Домен | Основні маршрути |
|---|---|
| Стан і identity | `GET /api/health`, `GET /api/config` (public), `GET /api/me` |
| Vault | `GET/POST /api/vault/items`, `GET/PUT/DELETE /api/vault/items/{id}`, versions, copy-event, sync-mode, collection, rotate-key, attachment metadata/content/delete |
| Імпорт і recovery | `/api/vault/imports/preview`, `/commit`; `/api/vault/reset-impact`, `/ownership-transfers`, `/reset` |
| Keys | `GET/PUT /api/keys/me`, `GET /api/keys/{email}`, `POST /api/keys/lookup` |
| Sharing | `/api/vault/items/{itemId}/permissions`: list/create/update/delete, members, provision, sync |
| Collections | `GET/POST /api/collections`, members, `directory-suggestions`, `sync-group`, rotate-key; `GET /api/collection-groups` |
| Directory/admin | `GET /api/directory/principals`; `/api/admin/workspace` refresh, status, users, groups, records; `/api/admin/tags` |
| External share | `POST/DELETE /api/vault/items/{itemId}/external-shares`, extend; public `GET /api/external-shares/{shareId}` |
| Passkeys | extension-only `POST/GET /api/passkeys`, counter, key-distribution, wrapped-keys |
| Audit | `GET /api/audit`, `/anomalies` для `ADMIN`/`SECURITY`; internal `POST /api/audit/keycloak-events` |
| Settings | `GET/PUT /api/settings`, avatar |

`/api/audit/keycloak-events` не має JWT, бо викликається Keycloak Event Listener; він вимагає constant-time перевірку `X-Keycloak-Events-Secret`, rate limit і не публікується nginx. Зовнішній share також public, тому має окремий, суворіший unauthenticated rate limit.

## 10. Edge, network і production security

nginx завершує TLS та встановлює HSTS, CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` і `Referrer-Policy: no-referrer`. Він:

- блокує зовнішній доступ до Actuator, крім `/actuator/health`, і до Swagger/OpenAPI;
- повертає 404 на Keycloak audit ingest, який доступний тільки у внутрішній мережі;
- перезаписує, а не додає `X-Forwarded-For`, тому клієнт не може підробити IP і обійти rate limit;
- вимикає request buffering та ліміт розміру для encrypted attachment stream, а також збільшує timeout-и для Drive transfer.

Backend незалежно від nginx теж deny-ить Swagger та non-health Actuator у production. `RateLimitFilter` обмежує звичайний API, public endpoint-и та key directory окремими лімітами. `trusted-proxies` треба задавати лише адресами/CIDR реальних proxy — порожнє значення безпечніше при прямому доступі до app.

Логи виходять у ECS JSON; `LoggingContextFilter` додає request ID і actor email. Actuator експонує health/info/Prometheus, а `/actuator/prometheus` має лишатися внутрішнім.

## 11. Ключові послідовності

### Створення і читання запису

```text
Unlock: passphrase → KDF → KEK → decrypt private key
Create: browser generates item key → AES-GCM encrypts fields → RSA-wraps item key → API persists opaque DTO
Read: API resolves access → returns ciphertext + caller's envelope → browser RSA-unwraps key → AES-GCM decrypts locally
```

### Group share

```text
Owner chooses a Workspace group → API resolves/snapshots members
→ permission members become active/pending according to policy
→ owner client wraps item/credential key for each intended recipient
→ API stores only envelopes; later Directory sync may reconcile membership
```

### Encrypted attachment

```text
Browser encrypts file + creates metadata → PUT opaque stream to API
→ API checks owner → stream to owner's Drive appDataFolder
→ persist Drive file ID + encrypted metadata → audit event
```

## 12. Загрози, гарантії та обмеження

| Сценарій | Захист | Межа гарантії |
|---|---|---|
| Витік БД або backup | Client-side AES-GCM і wrapped keys | Видно незашифровані metadata |
| Компрометація backend | Backend не має passphrase/raw item keys | Зловмисник може впливати на доступність або підміняти delivery без додаткових client-side assurances |
| Викрадений Google акаунт | Vault passphrase — окремий фактор; Keycloak passkey registration | Existing user може ще не мати required passkey, якщо створений до default policy |
| Insider `ADMIN` | Audit без vault decryption | Адмін все одно бачить метадані й audit |
| Revoke | Key rotation прибирає майбутній API-доступ | Не відкликає plaintext/ciphertext, уже скопійований отримувачем |
| Доступ за Google-групою | Local snapshot, policy, явні crypto envelopes | Group membership сама не розкриває item key |
| Brute force passphrase | Argon2id для нових keypair-ів; PBKDF2 legacy | Старі keypair-и не мігрують автоматично без passphrase |
| Public share / audit ingest | Tight rate limits, opaque package / shared secret, edge isolation | Secret треба ротути та тримати поза git |

## 13. Перевірка змін і навігація

`mvn test` покриває vault, sharing, collections, directory governance, audit, external share, passkeys і security filters. `FlywayMigrationIT` потребує Docker/Testcontainers; якщо Testcontainers не може дістатися Docker daemon, локальна альтернатива — PostgreSQL у звичайному контейнері та `ExternalPostgresSchemaValidationIT` з `PM_TEST_POSTGRES_URL`, `PM_TEST_POSTGRES_USER`, `PM_TEST_POSTGRES_PASSWORD`.

Окремо extension перевіряється `cd extension && npm test`; SPA — `cd frontend && npm run build`. Схему бази змінюють тільки новими Flyway migrations, а не `ddl-auto`.

Для конкретних процедур дивіться:

- [README.md](../README.md) — запуск і структура репозиторію;
- [KEYCLOAK.md](KEYCLOAK.md) — Google IdP, realm і WebAuthn;
- [DEPLOYMENT.md](DEPLOYMENT.md) — production configuration;
- [OPERATIONS.md](OPERATIONS.md) — backup, recovery і monitoring;
- [SECURITY.md](SECURITY.md) — security policy.
