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
2. З passphrase виводиться **KEK**: PBKDF2 (SHA-256, 210 000 ітерацій, per-user salt) → AES-256.
3. При першому вході браузер генерує **RSA-OAEP-2048 keypair**. Публічний ключ (SPKI) зберігається на сервері відкрито; приватний (PKCS8) — зашифрований KEK (AES-GCM). Тому vault працює з будь-якого пристрою: сервер віддає salt і зашифрований приватний ключ, а розшифрувати їх може лише власник passphrase (таблиця `user_keys`).
4. Кожен запис має власний **item key** (AES-256). Пароль і notes шифруються ним (AES-GCM, окремий IV на поле) ще в браузері.
5. Item key зберігається лише **загорнутим**: RSA-OAEP публічним ключем кожного, хто має доступ (таблиця `item_keys`, рядок на пару запис-користувач).
6. **Share**: owner розгортає item key своїм приватним ключем, обгортає публічним ключем отримувача (`GET /api/keys/{email}`) і передає разом із permission. **Revoke** видаляє і permission, і wrapped key.
7. **Local-only** записи не потрапляють на сервер: item key обгортається KEK і лежить поруч із ciphertext у localStorage.

**Обмеження (зафіксовано свідомо, див. [ROADMAP.md](ROADMAP.md)):**
- Group-share поки видає лише permission-метадані: член групи бачить запис, але не може розшифрувати без прямого share. Повне рішення — колекції з org-key (Фаза 3).
- Revoke не робить ротацію item key: колишній отримувач, який встиг зберегти ключ, теоретично розшифрує стару копію ciphertext. Ротація ключа при revoke — Фаза 3.
- Metadata (назва, URL, username, теги) зберігаються відкрито заради пошуку — за потреби їх теж можна шифрувати.
- KDF — PBKDF2; перехід на Argon2id заплановано (Фаза 5).

## Модель ролей

| Рівень | Ролі | Джерело |
|---|---|---|
| Застосунок (realm roles) | `user`, `admin`, `security` | Keycloak JWT `realm_access.roles` |
| Запис (permissions) | `OWNER` (з item), `EDITOR`, `VIEWER` (з таблиці permissions, per user або per group) | PostgreSQL |

- Owner може все: редагувати, видаляти, шерити, відкликати, міняти sync mode.
- Editor може змінювати запис, але не керує доступом.
- Viewer може переглядати/копіювати.
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
| Перебір passphrase | PBKDF2 210k ітерацій; далі — Argon2id на наступній ітерації |
| Підробка identity headers | Dev-заголовки `X-Dev-*` працюють лише в профілі `dev`; у prod — тільки підписаний JWT від Keycloak |

## Потік автентифікації

Користувач → застосунок → redirect на Keycloak → "Sign in with Google" → Google Workspace
підтверджує особу → Keycloak створює сесію, пропонує зареєструвати passkey (required action)
→ видає JWT → SPA викликає API з `Authorization: Bearer <token>` → Spring Boot валідує підпис,
issuer і мапить realm roles + groups.
