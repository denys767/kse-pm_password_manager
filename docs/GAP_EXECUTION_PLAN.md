# План закриття гепів із passwd.team — виконання субагентами

Джерело: [PASSWD_TEAM_GAP_ANALYSIS.md](PASSWD_TEAM_GAP_ANALYSIS.md), пріоритети 1–5.
Пункт 6 (mobile client, enterprise policies) свідомо поза цим планом.

Виконавці: Paseo-субагенти `codex/gpt-5.6-terra`, thinking `medium`, кожен у
власному worktree-workspace (branch-off від `main`). Оркестрація описана в
кінці документа.

## Інваріанти для КОЖНОГО агента (включати в prompt дослівно)

1. Сервер ніколи не бачить plaintext секретів і незагорнутих ключів. Уся
   криптографія — у браузері (WebCrypto, модель описана в ARCHITECTURE.md і
   ROADMAP.md, Фази 1/3).
2. Нові чутливі поля зберігаються тільки всередині encrypted payload запису
   або як окремий wrapped key — ніколи як відкриті колонки БД.
3. Схема БД змінюється лише новою Flyway-міграцією (`V6__...`, `V7__...`);
   `ddl-auto: validate` не чіпати.
4. Прибуття в main тільки зеленим: `mvn verify` (frontend build + backend +
   тести) і релевантний Playwright E2E.
5. Перед стартом прочитати: `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`,
   `docs/PASSWD_TEAM_GAP_ANALYSIS.md`. Наприкінці — оновити ROADMAP.md і
   gap-аналіз (позначити, що закрито).
6. Зовнішні npm-пакети можуть бути заблоковані політикою workspace —
   спочатку перевірити, чи ставляться; якщо ні, реалізувати локально
   (прецедент: локальна passphrase-політика замість zxcvbn-ts).

## Хвиля 1 — чотири паралельні агенти

### T1. Secret templates + TOTP (геп №2)

**Мета:** типізовані записи (LOGIN, API_CREDENTIALS, SSH_KEY, CARD,
SECURE_NOTE) і TOTP-коди для login-записів.

- `type` — нова колонка на `password_items` (V6-міграція); всі
  типоспецифічні поля живуть усередині наявного encrypted payload, тож
  backend лишається agnostic до вмісту.
- TOTP: зашифрований seed як поле payload; генерація RFC 6238 повністю в
  браузері (HMAC через WebCrypto), UI показує код із countdown і copy;
  seed ніколи не покидає браузер незашифрованим.
- Ключові файли: `frontend/src/types.ts`, `crypto.ts`,
  `components/ItemDialog.tsx`, `components/VaultTab.tsx`, `csv.ts`
  (експорт/імпорт нових типів), модуль `vault/` на backend, нова міграція.
- **Приймання:** `mvn verify`; Playwright: створення запису кожного типу,
  TOTP-код рендериться і змінюється після ротації вікна; CSV round-trip
  для нових типів.

### T2. Локальний security dashboard (геп №3)

**Мета:** вкладка Dashboard: weak / reused / old / breached секрети.

- Усе рахується на клієнті після unlock: weak — наявна локальна
  strength-оцінка (`passwords.ts`/`passphrase.ts`), reused — порівняння
  розшифрованих паролів у пам'яті, old — вік від останнього update
  (updatedAt / `password_item_versions`), breached — наявний HIBP
  k-anonymity flow із батчингом і throttle.
- На сервер не йде нічого, крім SHA-1-префіксів HIBP (як зараз).
- Ключові файли: новий `components/DashboardTab.tsx`, `App.tsx`
  (вкладка), `passwords.ts`. Backend не чіпати.
- **Приймання:** Playwright: сід зі слабким, повтореним і старим записом —
  дашборд показує їх у правильних категоріях; порожній стан коректний.

### T3. Lifecycle Google/Keycloak-груп із E2E provisioning (геп №4, розгорнуто в gap-аналізі)

**Мета:** замість вільного текстового поля `Keycloak group` — керований
життєвий цикл: selector дозволених груп, автоматичний diff membership,
черга безпечного E2E-провізіонування, ротація при виключенні.

- **Allowlist груп:** нова таблиця (V6/V7) дозволених до показу груп;
  admin-ендпоїнт керування нею; `GET` списку доступних груп через наявний
  `KeycloakAdminClient` (service account `kse-pm-admin`). У
  `CollectionsTab.tsx` — selector замість текстового поля.
- **Sync membership:** on-demand + періодичний diff членів Keycloak-групи
  проти членів колекції. Нові → статус `PENDING_PROVISIONING` (видимий
  MANAGER-у банер: «N учасників чекають на ключ»); MANAGER одним кліком
  обгортає collection key RSA-публічним ключем кожного pending-учасника —
  строго client-side. Вилучені з групи → `removeMember` + наявна ротація
  `POST /api/collections/{id}/rotate-key`.
- **Інваріант гепу:** членство в групі САМЕ ПО СОБІ ніколи не дає ключ;
  доступ з'являється лише після client-side wrapping ключа тим, хто його
  вже має. Створення/редагування груп лишається в Google
  Workspace/Keycloak — застосунок їх тільки читає.
- Ключові файли: `keycloak/KeycloakAdminClient.java`, модуль
  `collections/`, `CollectionsTab.tsx`, міграція; audit-події
  (`COLLECTION_MEMBER_PENDING`, `COLLECTION_SYNC` тощо).
- **Приймання:** unit-тести diff/lifecycle (у стилі наявного
  детермінованого HTTP-тесту KeycloakAdminClient, включно з 401 і
  порожньою групою); Playwright: вибір групи із selector-а → новий член у
  групі → pending → MANAGER провізіонує → член розшифровує; вилучення з
  групи → ротація, доступу немає.

### T4. Browser extension MV3 з autofill (геп №1)

**Мета:** MVP-розширення Chrome (Manifest V3) у новому каталозі
`extension/`.

- Scope MVP: OIDC-логін через Keycloak (Authorization Code + PKCE),
  unlock passphrase-ом, локальне розшифрування (переиспользувати логіку
  `crypto.ts` — винести спільний код або скопіювати з приміткою про
  джерело), пошук записів, autofill username/password по збігу origin,
  copy у clipboard з автоочищенням. Auto-save нових паролів — поза MVP.
- Новий каталог ⇒ мінімум конфліктів з іншими агентами; в основний код —
  лише якщо треба CORS/redirect URI-нюанси (окремим маленьким комітом).
- **Приймання:** розширення збирається; автоматизований тест логіки
  (matching origin, розшифрування фікстури); ручний чекліст у
  `extension/README.md` для повного E2E у Chrome.

## Хвиля 2 — після мержу хвилі 1

### T5. Timed external sharing (геп №5)

**Мета:** тимчасове посилання назовні як окремий encrypted package.

- Браузер відправника генерує одноразовий AES-ключ, шифрує ним снапшот
  полів запису; сервер зберігає тільки package + expiry + опційний
  one-time-view лічильник (V7/V8-міграція). Ключ передається у fragment
  URL (`#...`) — на сервер не потрапляє ніколи.
- Публічний ендпоїнт віддає package до expiry; після — 410; one-time —
  видалення після першого read. Rate limit наявним механізмом. Audit:
  `EXTERNAL_SHARE_CREATED/VIEWED/EXPIRED/REVOKED`; revoke вручну.
- Залежність від T1: снапшот має вміти типізовані payload-и — тому хвиля 2.
- **Приймання:** Playwright: створити лінк → відкрити в чистому контексті
  без сесії → розшифрувати; після expiry/одного перегляду — 410; у БД і
  логах немає ключа.

## Оркестрація (для агента-оркестратора)

Для кожної задачі:

```
create_workspace { isolation: "worktree", mode: "branch-off",
                   branchName: "gap-t<N>-<slug>", baseBranch: "main" }
create_agent     { title: "T<N>: <назва>",
                   provider: "codex/gpt-5.6-terra",
                   settings: { thinkingOptionId: "medium" },
                   workspaceId: <із попереднього кроку>,
                   notifyOnFinish: true,
                   initialPrompt: <секція задачі + блок інваріантів> }
```

- Хвиля 1: T1–T4 стартують паралельно. T5 — тільки після мержу T1.
- Рекомендований порядок мержу (мінімум конфліктів): **T2 → T1 → T3 → T4
  → T5**; T1 і T2 обидва торкаються `App.tsx`/vault-UI — той, хто
  мержиться другим, ребейзиться.
- Кожен агент завершує PR-ом у `main`; CI (`mvn verify`) — гейт мержу.
- Після кожного мержу — оновити статуси тут і в ROADMAP.md.

| Задача | Геп | Обсяг | Залежності |
| --- | --- | --- | --- |
| T1 templates + TOTP | №2 | середній | — |
| T2 security dashboard | №3 | малий (front-only) | — |
| T3 group lifecycle + E2E provisioning | №4 | великий | — |
| T4 browser extension MVP | №1 | великий (ізольований) | — |
| T5 timed external sharing | №5 | середній | T1 змержено |
