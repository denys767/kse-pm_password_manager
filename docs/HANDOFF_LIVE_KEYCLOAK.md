# Handoff: живий Keycloak-контур (для агента в середовищі з робочим Docker)

## Навіщо цей документ

Ця сесія довела продукт до стану, де **все, що можна побудувати й перевірити без живого
Keycloak, зроблено й верифіковано** (Фази 1–4 ROADMAP.md: E2E key wrapping, ротація ключів,
Collections, generator/HIBP/CSV, OpenAPI, CI, Docker/nginx, rate limiting, Prometheus,
алерти на аномалії, структуровані логи, Argon2id KDF — усе з тестами й живими прогонами).

Далі йдуть **виключно Keycloak-залежні пункти**. У поточному sandbox-середовищі
Docker-демон не запущений (`docker info` показує клієнт, але `docker ps` не може
підключитись до сокета — `dial unix /var/run/docker.sock: connect: no such file or directory`),
тому їх неможливо ані побудувати з реальною зворотною перевіркою, ані верифікувати живим
браузерним E2E. Писати цей код "наосліп" — свідомо гірша практика, ніж усе, що зроблено
досі в цьому репо (кожна попередня фіча пройшла: `mvn test` → live curl/dev-прогін →
Playwright E2E у справжньому Chromium → регресія). Тому передаю це середовищу, де є
робочий Docker.

**Гілка:** `claude/password-manager-backlog-4sgorl` (останній коміт `865ad9c`, запушено).
Перед стартом: `git pull origin claude/password-manager-backlog-4sgorl`.

## Що вже готово й чекає на live-верифікацію (код написаний, не тестований проти живого Keycloak)

### 1. OIDC-флоу (Authorization Code + PKCE)
Код повністю готовий:
- `frontend/src/auth.ts` — `initOidc()` через `keycloak-js`, автооновлення токена, `oidcLogout()`.
- `frontend/src/App.tsx` — читає `/api/config` (`ConfigController.java`), перемикає
  dev-headers/oidc режим.
- Backend: `SecurityConfig.java` — OAuth2 resource server, `JwtAuthenticationConverter`
  мапить `realm_access.roles` → `ROLE_*`; `AuthFacade.java` дістає email/name/groups з JWT.

**Що зробити:**
1. `docker compose up -d` (з кореня репо) — піднімає PostgreSQL + Keycloak, автоімпортує
   `keycloak/realm-export.json`.
2. Отримати реальні Google OAuth credentials: [KEYCLOAK.md](KEYCLOAK.md), розділ
   "Google Workspace як identity provider" — покроково, включно з redirect URI.
   Вставити в Keycloak Admin Console (`http://localhost:8081`, admin/admin) →
   realm `kse-pm` → Identity providers → google. Якщо немає реального Google Workspace
   акаунта — можна тимчасово прибрати `hostedDomain: kse.org.ua` обмеження і
   використати звичайний Google-акаунт для перевірки самого протоколу.
3. `mvn spring-boot:run` (без `-Dspring-boot.run.profiles=dev`) — застосунок піде
   в prod-конфіг з `KEYCLOAK_ISSUER_URI=http://localhost:8081/realms/kse-pm`.
4. Відкрити `http://localhost:8080`, натиснути "Sign in" — має перекинути на Keycloak
   → Google → назад у застосунок з валідним vault.

**Критерій успіху:** вхід через Google без жодних dev-заголовків; `GET /api/me` повертає
реальний email/ролі/групи з JWT; logout справді завершує Keycloak SSO-сесію (не тільки
локальний Lock).

### 2. WebAuthn / passkey (Epic 7)
Покрокова інструкція вже в [KEYCLOAK.md](KEYCLOAK.md), розділ "WebAuthn / passkey як
другий фактор" — треба виконати руками в Keycloak Admin Console (копіювання browser flow,
додавання WebAuthn Authenticator step, Required Actions, WebAuthn Policy).

**Що зробити:** пройти всі 4 кроки з KEYCLOAK.md, потім:
- Протестувати реєстрацію passkey й вхід на Chrome (macOS/Windows), Safari (Touch ID),
  Windows Hello — тест-матриця вже позначена в KEYCLOAK.md.
- Додати короткий UX-текст на фронті, якщо Keycloak-екран реєстрації passkey виглядає
  незрозуміло без пояснення (зараз увесь UX passkey — на боці Keycloak, фронт нічого не
  показує; вирішити на місці, чи потрібна прошарок-сторінка).

**Критерій успіху:** новий користувач при першому вході змушений зареєструвати passkey;
наступний вхід або запитує passkey, або (якщо biometric недоступний) fallback на recovery
code — обидва шляхи пройдені руками хоч на одній платформі.

## Що ще НЕ побудовано — нова робота, яка потребує живого Keycloak на кожному кроці розробки

### 3. Keycloak group sync для Collections (Admin API)
**Навіщо:** зараз членство в колекції (`collection_members`) — суто явне: manager вручну
додає кожен email і провізіонує йому wrapped collection key (`CollectionsTab.tsx`,
`CollectionService.java`). Це правильно з точки зору E2E-крипто (тільки той, хто вже має
ключ колекції, може обгорнути його для новачка — сервер фізично не може це зробити сам),
але зручно було б підказувати manager-у, кого з Keycloak-групи (`dev-team`, `finance` —
вже є в `realm-export.json`) ще не додано до колекції.

**Дизайн (не заблокований, просто не був пріоритетом без можливості live-тесту):**
- Новий Keycloak client `kse-pm-admin` — confidential, service account увімкнено, ролі
  `view-users` (мінімум; `manage-users` не потрібен — тільки читання складу групи) з
  `realm-management` client. Додати в `realm-export.json`.
- Backend: `KeycloakAdminClient` (новий клас, напр. `ua.kse.passwordmanager.keys` або
  окремий пакет `keycloak/`) — client_credentials grant проти
  `{issuer}/protocol/openid-connect/token`, потім
  `GET {keycloakBaseUrl}/admin/realms/{realm}/groups?search={name}` →
  `GET .../groups/{groupId}/members` (Keycloak Admin REST API). Секрет client'а — через
  `application.yml`/env var (`KEYCLOAK_ADMIN_CLIENT_SECRET`), той самий підхід, що й
  `KEYCLOAK_ISSUER_URI`.
- Endpoint `GET /api/collections/{id}/keycloak-suggestions?group=dev-team` (лише manager) —
  повертає email-и з Keycloak-групи, яких ще нема в `collection_members` (diff).
- Frontend: у `CollectionsTab.tsx` — поле "Keycloak group" (опційне, зберігати як
  `collections.keycloak_group`, нова колонка) + кнопка "Suggest members" → список чекбоксів
  → manager все одно тисне "Add" на кожного (wrapping ключа лишається client-side, як і
  зараз — це підказка складу, не автоматичне надання доступу).

**Як верифікувати (обов'язково, не пропускати):**
- Backend-тест з мокнутим HTTP-сервером (напр. WireMock або простий
  `com.sun.net.httpserver.HttpServer`) замість реального Keycloak — щоб `KeycloakAdminClient`
  мав детерміновану unit/integration перевірку незалежно від живого стенду.
- Живий прогін проти реального Keycloak з піднятого docker-compose: створити group у
  Keycloak, додати туди тестового користувача, викликати endpoint, звірити відповідь.
- Playwright E2E: manager бачить підказку, додає одного з запропонованих — той реально
  отримує доступ (той самий ланцюжок ключів, що вже перевірений у
  `e2e-collections.mjs`/`e2e-rotation.mjs` у scratchpad попередньої сесії — патерн
  перевикористати).

### 4. Keycloak event listener → audit LOGIN-подій
**Навіщо:** зараз `audit_events` фіксує лише дії всередині застосунку (create/share/revoke/
copy тощо), не сам факт входу через Keycloak. Для повноцінного audit trail (і для
`AuditAnomalyService`, який вже вміє детектити сплески — `audit/AuditAnomalyService.java`)
бракує LOGIN/LOGOUT подій.

**Дизайн:**
- Найпростіший шлях без кастомного Keycloak SPI: Keycloak вміє слати **webhooks** через
  вбудований `Event Listener` → `http` (у новіших версіях) або через сторонній
  `keycloak-http-event-listener` provider — перевірити, яка версія Keycloak у
  `docker-compose.yml` (`quay.io/keycloak/keycloak:26.0`) підтримує з коробки.
  Альтернатива, якщо вбудованого HTTP-листенера нема: написати мінімальний
  custom Keycloak SPI provider (Java, окремий Maven-модуль, JAR кладеться в
  `/opt/keycloak/providers/`) — це найбільша інвазивна частина роботи, тому спершу
  перевірити вбудовані опції.
- Новий endpoint `POST /api/audit/keycloak-events` (internal, захищений спільним секретом
  або мережевою ізоляцією — Keycloak і застосунок в одній docker-мережі, ендпоінт не
  виставляти назовні через nginx) — приймає LOGIN_ERROR/LOGIN/LOGOUT події, мапить у
  `AuditAction.LOGIN`/`LOGIN_FAILED`/`LOGOUT` (нові значення enum), зберігає через
  `AuditService.record(...)`.

**Як верифікувати:** живий вхід через Google в Keycloak → перевірити, що з'явився
відповідний `AuditEvent` через `GET /api/audit` (той самий admin/security-guard, що й
зараз) → перевірити, що `AuditAnomalyService` враховує нові LOGIN-події в детекції
сплесків (можна додати LOGIN у `DEFAULT_THRESHOLDS`, якщо є сенс — напр. сплеск невдалих
LOGIN_ERROR як ознака brute-force).

## Загальний checklist якості (той самий стандарт, що й у всій попередній роботі)

Для кожного з 4 пунктів вище:
1. `mvn test -Dfrontend.skip=true` — усі існуючі 31 + нові тести зелені.
2. `cd frontend && npm run build` — типи без помилок.
3. Живий прогін: `docker compose up -d`, реальний curl/API-виклик, перевірка відповіді.
4. Playwright E2E у браузері (Chromium вже передвстановлений — дивись, як були написані
   `e2e.mjs`/`e2e-collections.mjs`/`e2e-rotation.mjs`/`e2e-argon2.mjs` у scratchpad
   попередніх сесій — патерн: unlock двох користувачів, дія, перевірка результату в DOM).
5. Регресія: короткий повторний прогін одного з існуючих E2E-сценаріїв (share/decrypt),
   щоб підтвердити, що нічого не зламано.
6. Оновити `docs/ROADMAP.md`/`docs/ARCHITECTURE.md` — позначити ✅, описати рішення й
   свідомі обмеження (як зроблено для всіх попередніх пунктів).
7. Commit + push у ту саму гілку `claude/password-manager-backlog-4sgorl`.

## Контекст, який варто прочитати перед стартом

- `docs/ROADMAP.md` — повна історія фаз, що зроблено і чому саме так.
- `docs/ARCHITECTURE.md` — модель шифрування, ролі, threat model, API-таблиця.
- `docs/KEYCLOAK.md` — вже написана інструкція для пунктів 1–2.
- `docs/OPERATIONS.md` — бекапи, логи, чекліст перед проду.
- `keycloak/realm-export.json` — поточна конфігурація realm (client, ролі, groups-mapper,
  Google IdP placeholder).
