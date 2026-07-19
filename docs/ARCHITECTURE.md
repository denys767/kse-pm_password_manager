# Архітектура (Epic 2)

## Компоненти

```
Браузер (frontend shell + WebCrypto)
        │  HTTPS
        ▼
Reverse proxy (nginx / traefik — TLS termination, prod)
        │
        ├──► Spring Boot backend (REST API, перевірка JWT, permissions, audit)
        │            │
        │            ▼
        │       PostgreSQL (зашифровані записи, permissions, audit log, settings)
        │
        └──► Keycloak (SSO: Google Workspace → Keycloak → застосунок; WebAuthn 2FA)
```

- **Frontend** — статичний shell (`src/main/resources/static`), шифрує секрети в браузері через WebCrypto до відправки на сервер.
- **Backend** — Spring Boot 3 (Java 21), модулі-пакети: `auth`, `vault`, `sharing`, `audit`, `settings`, `common`.
- **Keycloak** — identity broker для Google Workspace, видає JWT; backend — OAuth2 resource server.
- **PostgreSQL** — зберігає тільки ciphertext паролів/notes, метадані, permissions та audit events.

## Модель шифрування: E2E з per-item key wrapping

Сервер ніколи не зберігає відкриті паролі й ніколи не бачить незагорнуті ключі.

1. Користувач вводить **vault passphrase** у браузері. Вона ніколи не надсилається на сервер.
2. З passphrase виводиться **KEK** (AES-256): нові keypair-и — через **Argon2id** (`hash-wasm`, m=19 MiB/t=2/p=1, OWASP-рекомендація для constrained/browser середовищ; memory-hard — значно дорожче брутфорсити на GPU/ASIC за той самий wall-clock час unlock, ніж PBKDF2). `UserKeys.kdfAlgorithm` версіонує алгоритм на кожен keypair (`PBKDF2`/`ARGON2ID`) — keypair-и, зареєстровані до появи Argon2id, і далі розшифровуються PBKDF2 (SHA-256, 210k ітерацій), без примусової міграції: перевивести KEK можна лише з passphrase користувача, якого сервер не має.
3. При першому вході браузер генерує **RSA-OAEP-2048 keypair**. Публічний ключ (SPKI) зберігається на сервері відкрито; приватний (PKCS8) — зашифрований KEK (AES-GCM). Тому vault працює з будь-якого пристрою: сервер віддає salt і зашифрований приватний ключ, а розшифрувати їх може лише власник passphrase (таблиця `user_keys`).
4. Кожен запис має власний **item key** (AES-256). Пароль і notes шифруються ним (AES-GCM, окремий IV на поле) ще в браузері.
5. Item key зберігається лише **загорнутим**: RSA-OAEP публічним ключем кожного, хто має доступ (таблиця `item_keys`, рядок на пару запис-користувач).
6. **Share (прямий, user-to-user)**: owner розгортає item key своїм приватним ключем, обгортає публічним ключем отримувача (`GET /api/keys/{email}`) і передає разом із permission. **Revoke** видаляє permission, wrapped key і (якщо лишились інші отримувачі) ротує item key — див. пункт 9.
7. **Collections (командний доступ)**: колекція має власний **collection key** (AES-256), який зберігається лише обгорнутим публічним ключем кожного члена (таблиця `collection_members.wrapped_key`). Item key записів у колекції обгортається AES-GCM ключем колекції (`password_items.collection_wrapped_key`), а не RSA — тому додавання нового члена не потребує перешифрування жодного запису, лише один RSA-wrap колекційного ключа для новачка. Ланцюжок розшифрування учасника: приватний ключ → (RSA-unwrap) collection key → (AES-unwrap) item key → поля. Додати члена може лише той, хто вже має ключ колекції (MANAGER) — це і є причина, чому склад членів явний (email), а не автоматично синхронізований з Keycloak-групами.
8. **Local-only** записи не потрапляють на сервер: item key обгортається KEK і лежить поруч із ciphertext у localStorage.
9. **Ротація ключа (crypto-shredding) при revoke**: клієнт власника генерує новий ключ, перешифровує ним дані і перегортає для всіх, хто лишається доступу — сервер лише зберігає результат. Для прямого share — `POST /api/vault/items/{id}/rotate-key` (новий item key, нові `encryptedPassword`/`encryptedNotes`, нові wrapped-записи в `item_keys` для owner + залишених отримувачів; старі рядки видаляються). Для колекцій — `POST /api/collections/{id}/rotate-key` (новий collection key, нові `wrapped_key` залишених членів, нові `collection_wrapped_key` усіх записів колекції). Обидва endpoints власник/manager викликає **до** видалення permission/membership. Ротація прямого share пропускається для записів у колекції (`PasswordItem.collectionId != null` → 400) — там діє ротація колекційного ключа.

**Обмеження (зафіксовано свідомо, див. [ROADMAP.md](ROADMAP.md)):**
- Прямий group-share (permission з `granteeType=GROUP`, без колекції) видає лише метадані: член довільної Keycloak-групи бачить запис, але не може розшифрувати без прямого share або колекції. Для реального командного доступу використовуйте Collections.
- Ротація (пункт 9) захищає лише майбутні зміни й майбутні читання через API — не захист від пристрою, що вже мав ciphertext на момент компрометації (властивість crypto-shredding, не баг).
- Metadata (назва, URL, username, теги) зберігаються відкрито заради пошуку — за потреби їх теж можна шифрувати.
- KDF версіонується per-keypair (`PBKDF2`/`ARGON2ID`) — нема глобальної примусової міграції, старі keypair-и лишаються на PBKDF2 назавжди, якщо власник не змінить passphrase (що перевиводить KEK і може оновити алгоритм).
- Синхронізація складу колекції з Keycloak-групами через Admin API — не зроблено; членство поки суто явне.

## Модель ролей

| Рівень | Ролі | Джерело |
|---|---|---|
| Застосунок (realm roles) | `user`, `admin`, `security` | Keycloak JWT `realm_access.roles` |
| Запис (permissions) | `OWNER` (з item), `EDITOR`, `VIEWER` (з таблиці permissions, per user або per group) | PostgreSQL |
| Колекція (membership) | `MANAGER`, `EDITOR`, `VIEWER` (з таблиці `collection_members`) | PostgreSQL |

- Owner може все: редагувати, видаляти, шерити, відкликати, міняти sync mode, переносити між колекціями.
- Editor (прямий share або колекція) може змінювати запис, але не керує доступом.
- Viewer може переглядати/копіювати.
- У колекції MANAGER додатково додає/видаляє членів і змінює ролі; owner колекції завжди MANAGER і не може бути видалений чи понижений.
- `admin`/`security` бачать audit log (`GET /api/audit`), але **не** отримують автоматичного доступу до чужих записів — сервер все одно не може їх розшифрувати.

## API-first

Уся функціональність доступна через REST API (`/api/**`), frontend — лише один із клієнтів. Мобільна апка використовуватиме ті самі endpoints із тим самим Keycloak JWT:

| Метод | Шлях | Опис |
|---|---|---|
| GET | `/api/health` | Health (public) |
| GET | `/api/me` | Поточний користувач, ролі, групи |
| GET/POST | `/api/vault/items` | Список / створення |
| GET/PUT/DELETE | `/api/vault/items/{id}` | Один запис |
| POST | `/api/vault/items/{id}/copy-event` | Audit події копіювання |
| PATCH | `/api/vault/items/{id}/sync-mode` | Toggle "зберігати на сервері" |
| GET/POST | `/api/vault/items/{id}/permissions` | Доступи (owner) |
| DELETE | `/api/vault/items/{id}/permissions/{permId}` | Revoke (owner) |
| POST | `/api/vault/items/{id}/rotate-key` | Ротація item key (owner, перед revoke) |
| GET | `/api/vault/items/{id}/versions` | Історія версій |
| PUT | `/api/vault/items/{id}/collection` | Додати/зняти запис з колекції (owner) |
| GET/POST | `/api/collections` | Мої колекції / створення |
| GET/POST | `/api/collections/{id}/members` | Члени колекції / додати (manager) |
| PUT/DELETE | `/api/collections/{id}/members/{memberId}` | Змінити роль / revoke (manager) |
| POST | `/api/collections/{id}/rotate-key` | Ротація collection key (manager, перед видаленням члена) |
| DELETE | `/api/collections/{id}` | Видалити порожню колекцію (owner) |
| GET/PUT | `/api/keys/me`, GET `/api/keys/{email}` | Keypair користувача / публічний ключ іншого |
| GET | `/api/audit` | Audit log (admin/security) |
| GET/PUT | `/api/settings` | Налаштування користувача |

## Базовий threat model

| Загроза | Мітигація |
|---|---|
| Компрометація БД / бекап | Паролі зашифровані на клієнті AES-GCM; сервер не має ключа |
| Компрометація backend | Те саме: plaintext секрети через backend не проходять |
| Пересилання паролів у чатах | Sharing через permissions + revoke, все в audit log |
| Викрадений акаунт Google | WebAuthn/passkey як другий фактор у Keycloak |
| Insider з роллю admin | Admin бачить audit log, але не може розшифрувати записи |
| Викрадений пристрій | Vault замкнено passphrase; local-only записи зашифровані в localStorage |
| Clipboard sniffing | Автоочищення clipboard через N секунд (налаштовується) |
| Перебір passphrase | Argon2id (memory-hard) для нових keypair-ів; PBKDF2 210k ітерацій для старих |
| Підробка identity headers | Dev-заголовки `X-Dev-*` працюють лише в профілі `dev`; у prod — тільки підписаний JWT від Keycloak |

## Потік автентифікації

Користувач → застосунок → redirect на Keycloak → "Sign in with Google" → Google Workspace
підтверджує особу → Keycloak створює сесію, пропонує зареєструвати passkey (required action)
→ видає JWT → SPA викликає API з `Authorization: Bearer <token>` → Spring Boot валідує підпис,
issuer і мапить realm roles + groups.
