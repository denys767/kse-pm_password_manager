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
  auth/      Keycloak JWT (prod) / header-auth (dev), /api/me, /api/health
  vault/     записи: CRUD, copy-event, sync-mode toggle
  sharing/   permissions (owner/editor/viewer, user/group), share/revoke
  audit/     audit log подій (create/view/update/delete/copy/share/revoke/sync)
  settings/  налаштування користувача (default sync mode, clipboard timeout)
src/main/resources/static/   frontend shell (WebCrypto client-side encryption)
keycloak/realm-export.json   realm kse-pm: client, ролі, groups-mapper, Google IdP
```

## Документація

- [Backlog, user journeys, user stories та алгоритм роботи](docs/BACKLOG.md)
- [Roadmap: фази розвитку від MVP до продукту](docs/ROADMAP.md)
- [Архітектура: компоненти, E2E-модель шифрування, ролі, threat model](docs/ARCHITECTURE.md)
- [Keycloak: Google Workspace SSO та WebAuthn/passkey](docs/KEYCLOAK.md)
