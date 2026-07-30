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
| Identity | Keycloak 26 + Google Workspace IdP | SSO, OAuth2/OIDC токени, passwordless WebAuthn, realm-конфігурація | Не є джерелом корпоративних ролей API |
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
3. Keycloak показує Google SSO та passwordless passkey як альтернативні способи входу; реєстрація passkey зараз добровільна
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

### Відкликання, втрата passphrase і відновлення

Перед revoke клієнт owner/manager виконує ротацію ключа: генерує новий item/collection key, повторно шифрує дані або envelope-и для тих, хто лишається, потім прибирає доступ. Це crypto-shredding для майбутніх API-чтень, але не може стерти ciphertext, уже скопійований на скомпрометований пристрій.

Серверного escrow і адміністративного «break-glass» доступу до vault **немає**. Якщо користувач забув passphrase, він проходить fresh SSO, оцінює вплив через recovery API, передає ownership shared records або collections наступнику, який уже має зашифрований доступ, а потім скидає vault і створює новий keypair. Особисті записи, не поширені до offboarding, відновити неможливо. Історичні recovery-таблиці не означають, що поточний deployment зберігає KMS-envelopes для розшифрування даних.

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
- **Додаткові можливості**: `external_shares`, `passkey_credentials`, `passkey_credential_keys`, історичні recovery-таблиці, `audit_events`.

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
| Викрадений Google акаунт | Vault passphrase — окремий фактор; Keycloak підтримує passkey | Passkey registration добровільна і не є MFA-перевіркою на кожному повторному вході |
| Insider `ADMIN` | Audit без vault decryption | Адмін все одно бачить метадані й audit |
| Revoke | Key rotation прибирає майбутній API-доступ | Не відкликає plaintext/ciphertext, уже скопійований отримувачем |
| Доступ за Google-групою | Local snapshot, policy, явні crypto envelopes | Group membership сама не розкриває item key |
| Brute force passphrase | Argon2id для нових keypair-ів; PBKDF2 legacy | Старі keypair-и не мігрують автоматично без passphrase |
| Public share / audit ingest | Tight rate limits, opaque package / shared secret, edge isolation | Secret треба ротути та тримати поза git |

## 13. Архітектура розгортання

### Production topology і build

`Dockerfile` — multi-stage build: Maven image збирає Java backend і React SPA, а runtime image містить лише Temurin JRE 21, jar та non-root користувача `app` (UID 1001). Контейнер app слухає внутрішній порт `8080`.

`docker-compose.prod.yml` створює такі сервіси:

| Сервіс | Призначення | Доступ ззовні | Persistent state |
|---|---|---|---|
| `nginx` | TLS edge, reverse proxy | `443` (app), `8443` (Keycloak) | TLS certificates, mounted read-only |
| `app` | Spring Boot + SPA | лише через nginx | немає, усі дані у Postgres/Drive |
| `postgres` | БД застосунку та Keycloak у production compose | ні | named volume `pgdata` |
| `keycloak` | SSO, IdP broker, OIDC clients | лише через nginx `:8443` | PostgreSQL schema |
| `keycloak-init` | одноразово зв'язує Account Console з Google re-auth flow | ні, завершується після роботи | немає |

Перед першим запуском визначають два різні публічні HTTPS origins, наприклад `https://pm.example.com` та `https://auth.pm.example.com`. Лише nginx публікує порти. Для Keycloak задають `KEYCLOAK_HOSTNAME=https://auth.pm.example.com`, для backend — `KEYCLOAK_ISSUER_URI=https://auth.pm.example.com/realms/kse-pm`; у клієнті `kse-pm-web` оновлюють valid redirects на `https://pm.example.com/*`, web origin на `https://pm.example.com` та Google broker redirect на `https://auth.pm.example.com/realms/kse-pm/broker/google/endpoint`.

Нормальний запуск: `docker compose -f docker-compose.prod.yml up -d --build`. Перед введенням у експлуатацію перевіряють health, Google login/logout, роботу passkey, розшифрування запису та public external-share link. У TLS-директорії мають бути реальні сертифікати; self-signed підходить лише для staging.

### Конфігураційні межі та секрети

`example.env` є шаблоном, а не production secret store. У production секрети передаються через Secret Manager/Vault або захищений environment file; їх не можна включати до Docker image чи комітити. Критичні значення:

| Значення | Споживач | Призначення |
|---|---|---|
| `DB_PASSWORD` | app, PostgreSQL, Keycloak | пароль БД |
| `KEYCLOAK_ADMIN_PASSWORD` | Keycloak | bootstrap realm administrator, tier-0 секрет |
| `GOOGLE_CLIENT_SECRET` | Keycloak | обмін Google OAuth code на token |
| `KEYCLOAK_EVENTS_SECRET` | app + Keycloak listener | internal audit-event ingestion |
| `WORKSPACE_FEDERATION_CLIENT_SECRET` | Keycloak federation client + app | machine `client_credentials` для WIF |
| `GOOGLE_WORKSPACE_CREDENTIALS_PATH` | app, лише fallback | mounted read-only JSON service-account key |
| `GOOGLE_WORKSPACE_SERVICE_ACCOUNT_EMAIL`, `GOOGLE_WORKSPACE_ADMIN_EMAIL` | app | target service account і delegation subject |
| `GOOGLE_WORKSPACE_DOMAIN`, `GOOGLE_WORKSPACE_CUSTOMER_ID` | app | межа Workspace directory sync |

`KEYCLOAK_EVENTS_SECRET` є необхідним у production compose, хоча стандартний Keycloak image ще не містить HTTP Event Listener provider: endpoint готовий і захищений, але автоматична доставка подій не почнеться, доки не буде розгорнуто й перевірено власний або сторонній SPI.

### Keycloak production configuration

Realm import містить web client `kse-pm-web` (Authorization Code + PKCE), public extension client `kse-pm-extension` (Authorization Code + PKCE S256) і confidential non-interactive `kse-pm-federation` для workload identity. Google є identity broker; `hostedDomain` лише обмежує login UX і не замінює local Workspace governance.

Keycloak запускається з feature `passkeys`. Browser flow тримає Google redirector і `webauthn-authenticator-passwordless` як `ALTERNATIVE`: жоден із них не слід вимикати, інакше login flow не матиме execution, який може автентифікувати користувача. У поточному realm `webauthn-register-passwordless.defaultAction=false`, тому первинна реєстрація passkey добровільна. Account Console може додавати passkey через client-level override `browser-google-reauth`; `keycloak-init` накладає цей override, налаштовує read-only email/profile і вимикає update profile при first Google login.

Passkey не є примусовою другою перевіркою після кожного Google login: така схема через post-broker flow ламала створення нових користувачів, бо до завершення First Broker Login локальний користувач ще не існує. Перед compliance-твердженнями про MFA це обмеження треба врахувати; перспективний шлях — окремий Keycloak SPI/authenticator з явною обробкою відсутнього user context. Біометричні дані не надходять у Keycloak чи застосунок — платформа повертає лише WebAuthn assertion.

### Розгортання Chrome extension

Extension збирається окремо й публікується зі стабільною Chrome identity:

```bash
cd extension
VITE_API_ORIGIN=https://pm.example.com VITE_OIDC_CLIENT_ID=kse-pm-extension npm ci
VITE_API_ORIGIN=https://pm.example.com VITE_OIDC_CLIENT_ID=kse-pm-extension npm run build
```

У Keycloak для `kse-pm-extension` задають точний redirect `https://pm.example.com/extension-callback`. Вхід відкриває normal browser tab, бо `chrome.identity.launchWebAuthFlow` не дає надійного контексту для platform-WebAuthn Keycloak login. Callback page передає authorization code extension через `chrome.runtime.sendMessage`; token exchange виконує background worker, а callback tab закривається.

Build підставляє deployment origin в `externally_connectable`. SPA ще раз перевіряє extension ID із `/api/config`, а extension перевіряє origin bridge-підключення. Vault passkey extension сам не виконує: PRF-wrapped passphrase прив'язаний до RP ID вебзастосунку у його `localStorage`. Тому app виконує ceremony і передає passphrase extension; lock синхронізується в обидва боки, unlock — тільки app → extension. Потрібний Chrome 115+; на lock/logout virtual authenticator від'єднується, щоб Chrome міг використати системний authenticator.

## 14. Google Workspace: credential modes, resilience і мінімальні права

Для Directory та Drive застосунок завжди створює короткоживучий domain-wide delegated token. У Workspace Admin Console OAuth Client ID service account дозволяють **лише** такі scopes:

```text
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.group.readonly
https://www.googleapis.com/auth/admin.directory.group.member.readonly
https://www.googleapis.com/auth/drive.appdata
```

Не можна замінювати їх write Directory scope або загальним `drive`: перший дає керування акаунтами, другий відкриває більше ніж зашифрований `appDataFolder`. Delegation subject повинен бути окремим non-human ліцензованим акаунтом із custom role «Users Read / Groups Read», не super-admin.

| Режим | Коли використовувати | Ланцюжок довіри | Заборони/ризики |
|---|---|---|---|
| A — Workload Identity Federation | рекомендований поза GCP | app → Keycloak confidential client → Google STS → IAM `signJwt` → DWD token | Не давати pool-wide `principalSet://…/*`; Keycloak issuer має бути HTTPS/JWKS-reachable |
| B — attached service account | GCE/GKE | metadata ADC → IAM `signJwt` → DWD token | attached identity має бути scoped до target SA `TokenCreator` |
| C — service-account key | лише коли A/B неможливі | mounted JSON key локально підписує delegation assertion | довгоживучий tier-0 secret; mount RO, rotate поза git |

Людський `gcloud auth application-default login` придатний тільки для локальної розробки: Google re-auth policy робить його непридатним для 24/7 сервісу. Application показує це в directory status (`credentialUnattended=false`) і під `prod` профілем відмовляється стартувати з таким credential.

Для WIF provider обов'язкові дві незалежні GCP-обмежувальні умови:

1. `--attribute-condition="assertion.azp == 'kse-pm-federation'"`, щоб той самий Keycloak realm не допускав до pool токени звичайних користувачів.
2. `roles/iam.serviceAccountTokenCreator` тільки для одного `principal://…/subject/<Keycloak service-account sub>`, а не для pool/provider/`principalSet`.

`sub` беруть із реального client-credentials token, а не вгадують; його треба оновити в IAM binding після recreation realm або client. Якщо issuer не можна зробити externally reachable із trusted TLS, WIF provider створюють із pinned realm JWKS і оновлюють при ротації signing key.

### Поведінка під час Google outage

Старт app не залежить від доступності Google. Токен, уже отриманий backend, використовується до expiry і proactively renews кожні 10 хвилин (`pm.google-workspace.token-refresh-ms`). Пошук recipients і directory suggestions у звичайному режимі читають materialized local snapshot — це і resilience, і захист від вичерпання квоти під час type-ahead. Sync оновлює Google кожні 15 хвилин; до першого успіху retry відбувається щохвилини. Membership resolution спершу питає Google, але має fallback на snapshot; сам synchronizer не синхронізується «із snapshot у snapshot», а лишає попередній стан та повторює спробу.

`GET /api/admin/workspace/directory-status` показує credential mode, unattended status, останній успішний sync, error і факт використання snapshot. Дозвіл `provisional-access-when-unsynced` — вузький fallback: лише email у configured domain, лише коли `workspace_users` порожня, лише роль `USER`, із WARN не частіше разу на хвилину. Після першого snapshot він припиняє діяти. Налаштування `WORKSPACE_PROVISIONAL_ACCESS=false` робить поведінку fail-closed.

## 15. Експлуатація, резервне копіювання і спостережуваність

### Дані та відновлення

PostgreSQL backup не розкриває паролі, але втрата backup означає втрату server-synced vault data, wrapped keys і metadata. Практичний runbook використовує щоденний custom-format `pg_dump`, зберігання поза хостом із versioning і retention, а також щомісячне test restore. До backup scope належить і Keycloak realm/його БД.

Відновлення роблять у порядку: підняти `postgres` і `keycloak`; виконати `pg_restore --clean --if-exists`; підняти `app` і `nginx`; Flyway звіряє версію схеми, Hibernate — mapping (`ddl-auto=validate`); потім перевірити `/api/health`, login і decrypt тестового запису. З server backup не відновлюються local-only items та passphrase. Force-reset keypair робить старі items нечитабельними, а не відновлює їх.

### Моніторинг та реакція

`/actuator/prometheus` доступний лише із внутрішньої мережі. Мінімальні alerts: `up == 0`; rate 5xx; rate 429 як сигнал brute-force/abuse; тривалий `hikaricp_connections_pending > 0`. `GET /api/audit/anomalies` для `ADMIN`/`SECURITY` знаходить порогові сплески copy/share/revoke та відображається banner-ом у UI; це проста евристика, не SIEM і не виявляє повільні або розподілені атаки.

Production logs — ECS JSON на stdout із `actorEmail` і request-scoped UUID `requestId`; `dev` залишає human-readable logging. Business audit і технічні логи доповнюють одне одного: перший фіксує дію, другі — хід обробки запиту.

Перед production launch потрібні реальні TLS сертифікати, замінені default паролі, відсутній `dev` profile/`PM_ALLOW_INSECURE_DEV`, налаштовані й перевірені backups, Google credentials/hosted domain, passkey UX та external security review/pentest.

## 16. Межі поточної реалізації та наступні кроки

- Прямий group-share відображає намір і policy, але не видає group members криптографічні envelope-и автоматично; для реального team E2E access використовують Collections.
- Login/logout audit endpoint перевірено вручну, але без EventListener SPI Keycloak не доставляє ці події автоматично.
- Rate limiter in-memory і per-node: перед horizontal scaling потрібен shared limiter на кшталт Redis/Bucket4j.
- Мобільний client (React Native) ще не реалізований, але REST API і crypto boundary спроєктовано API-first.
- Extension MVP сфокусований на Chrome; Firefox/Safari і enterprise deployment policy залишаються окремою роботою.
- Security dashboard виконує аналіз unlock-нутих записів лише локально: weak/reused/old (90+ days) і compromised password. Для HIBP у мережу йде тільки 5-symbol SHA-1 prefix; plaintext не передається.

## 17. Перевірка змін і навігація

`mvn test` покриває vault, sharing, collections, directory governance, audit, external share, passkeys і security filters. `FlywayMigrationIT` потребує Docker/Testcontainers; якщо Testcontainers не може дістатися Docker daemon, локальна альтернатива — PostgreSQL у звичайному контейнері та `ExternalPostgresSchemaValidationIT` з `PM_TEST_POSTGRES_URL`, `PM_TEST_POSTGRES_USER`, `PM_TEST_POSTGRES_PASSWORD`.

Окремо extension перевіряється `cd extension && npm test`; SPA — `cd frontend && npm run build`. Схему бази змінюють тільки новими Flyway migrations, а не `ddl-auto`.

Для конкретних процедур дивіться:

- [README.md](../README.md) — запуск і структура репозиторію;
- [KEYCLOAK.md](KEYCLOAK.md) — Google IdP, realm і WebAuthn;
- [DEPLOYMENT.md](DEPLOYMENT.md) — production configuration;
- [OPERATIONS.md](OPERATIONS.md) — backup, recovery і monitoring;
- [SECURITY.md](SECURITY.md) — security policy.
