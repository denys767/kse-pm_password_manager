# kse-pm_password_manager

Корпоративний менеджер паролів: централізоване зберігання доступів, sharing без пересилання паролів у чатах, audit log.

**Стек:** Spring Boot 3 (Java 21) · PostgreSQL · Keycloak + Google Workspace SSO · WebAuthn/passkey як другий фактор · client-side encryption (AES-GCM у браузері — сервер зберігає лише ciphertext).

## Швидкий старт (dev, без Keycloak)

```bash
PM_ALLOW_INSECURE_DEV=true mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

Відкрийте http://localhost:8080 — dev-режим використовує H2 in-memory і приймає
identity з полів на екрані Unlock (заголовки `X-Dev-User`/`X-Dev-Roles`/`X-Dev-Groups`).
Профіль `dev` призначений тільки для локальної розробки: без явного
`PM_ALLOW_INSECURE_DEV=true` застосунок відмовляється стартувати.

## Повний стек (PostgreSQL + Keycloak)

```bash
docker compose up -d      # PostgreSQL :5432, Keycloak :8081 (admin/admin, realm kse-pm)
mvn spring-boot:run       # backend перевіряє JWT від Keycloak
```

Налаштування Google Workspace SSO та WebAuthn — у [docs/KEYCLOAK.md](docs/KEYCLOAK.md).

## Production-подібний деплой

```bash
# TLS-сертифікати у nginx/certs/ (див. коментар у docker-compose.prod.yml), потім:
DB_PASSWORD=... KEYCLOAK_ADMIN_PASSWORD=... docker compose -f docker-compose.prod.yml up -d --build
```

nginx термінує TLS (застосунок на :443, Keycloak на :8443), додає HSTS/CSP/X-Frame-Options
і закриває `/actuator/*` (крім health) та Swagger ззовні. API задокументоване
через OpenAPI: `/swagger-ui.html` (dev/staging). Метрики: `/actuator/prometheus`.
Rate limit на API: 300 запитів/хв на IP (`pm.rate-limit.requests-per-minute`).

## Тести

```bash
mvn test
```

Інтеграційні тести покривають CRUD vault, права owner/editor/viewer, sharing з
користувачем і групою, revoke, заборону local-only для shared-записів,
sync-mode toggle і доступ до audit log.

## Структура

```
src/main/java/ua/kse/passwordmanager/
  auth/      Keycloak JWT (prod) / header-auth (dev), /api/me, /api/config
  keys/      user keypairs для E2E sharing (public + encrypted private key)
  vault/     записи: CRUD, item_keys (wrapped AES-ключі), sync-mode toggle
  sharing/   permissions (owner/editor/viewer, user/group), share/revoke
  audit/     audit log подій (create/view/update/delete/copy/share/revoke/sync)
  settings/  налаштування користувача (default sync mode, clipboard timeout)
src/main/resources/db/migration/   Flyway-міграції (PostgreSQL)
frontend/                    React + TypeScript SPA (Vite); crypto.ts — WebCrypto E2E
keycloak/realm-export.json   realm kse-pm: client, ролі, groups-mapper, Google IdP
```

Frontend збирається автоматично під час `mvn package`/`spring-boot:run`
(frontend-maven-plugin). Для backend-ітерацій: `-Dfrontend.skip=true`.
Окрема розробка UI: `cd frontend && npm run dev` (Vite dev server із proxy на :8080).

## Документація

- [Backlog, user journeys, user stories та алгоритм роботи](docs/BACKLOG.md)
- [Roadmap: фази розвитку від MVP до продукту](docs/ROADMAP.md)
- [Архітектура: компоненти, E2E-модель шифрування, ролі, threat model](docs/ARCHITECTURE.md)
- [Keycloak: Google Workspace SSO та WebAuthn/passkey](docs/KEYCLOAK.md)
- [Operations: бекапи, відновлення, моніторинг, чекліст запуску](docs/OPERATIONS.md)
- [Handoff: живий Keycloak-контур — що лишилось верифікувати/побудувати з робочим Docker](docs/HANDOFF_LIVE_KEYCLOAK.md)
