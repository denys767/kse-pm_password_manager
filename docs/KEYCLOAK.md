# Keycloak: Google Workspace SSO (Epic 4) та WebAuthn (Epic 7)

## Запуск

```bash
docker compose up -d
```

Піднімає PostgreSQL (`:5432`) і Keycloak (`:8081`, admin/admin) з автоімпортом realm
`kse-pm` із `keycloak/realm-export.json`: realm-ролі `user`/`admin`/`security`, public client
`kse-pm-web` (Authorization Code + PKCE), groups-mapper і Google identity provider.

## Google Workspace як identity provider

1. У [Google Cloud Console](https://console.cloud.google.com) створіть OAuth 2.0 Client ID
   (тип Web application) з redirect URI:
   `http://localhost:8081/realms/kse-pm/broker/google/endpoint`
2. Client Secret задається змінною середовища `GOOGLE_CLIENT_SECRET` (див.
   `example.env`) — `realm-export.json` містить лише плейсхолдер
   `${GOOGLE_CLIENT_SECRET}`, який Keycloak підставляє зі свого середовища при
   імпорті; `docker-compose.yml`/`docker-compose.prod.yml` прокидають цю змінну
   в контейнер Keycloak. Без неї "Sign in with Google" падає з узагальненою
   сторінкою Keycloak "We are sorry... Invalid username or password" (обмін
   коду на токен з Google повертає `invalid_client`). Client ID вже прописаний
   у файлі — новий створювати не потрібно, якщо не заводите власний Google Cloud
   проєкт.
3. `hostedDomain: kse.org.ua` обмежує вхід корпоративними акаунтами — вхід
   акаунтом поза цим доменом (наприклад особистий `@gmail.com` для локального
   тесту без адмін-доступу до Workspace) також падає з тим самим "We are
   sorry... Invalid username or password". Для демо на своєму домені тимчасово
   очистіть поле Hosted Domain у Identity providers → google (Admin Console)
   або в локальній копії `realm-export.json` перед імпортом, і поверніть
   значення `kse.org.ua` перед пушем/production.
4. Mapping email/name виконує сам брокер (`trustEmail: true`); групи мапляться
   protocol-mapper'ом `groups` у claim `groups` токена. Membership у групи
   (`dev-team`, `finance`, …) призначається в Keycloak → Users → Groups, ролі
   `admin`/`security` — у Role mapping.

Схема входу: **Google Workspace → Keycloak → застосунок**. Backend перевіряє JWT
(`KEYCLOAK_ISSUER_URI`, за замовчуванням `http://localhost:8081/realms/kse-pm`).

## Logout flow

Frontend викликає `GET {issuer}/protocol/openid-connect/logout?post_logout_redirect_uri=...&id_token_hint=...` —
Keycloak завершує SSO-сесію та повертає на застосунок; локально frontend чистить
ключ шифрування з пам'яті (кнопка **Lock** робить це без завершення SSO-сесії).

## WebAuthn / passkey як другий фактор (Epic 7)

> Account Console керує passkeys лише у Keycloak 26.4+ з увімкненим preview
> feature `passkeys` і `Enable Passkeys` у WebAuthn Passwordless Policy. У
> `docker-compose.yml` та `realm-export.json` це вже задано; після оновлення
> контейнера сторінка `Signing in` показує керування passkeys поруч із OTP.

> **Поточний стан входу (2026-07-23):** Browser flow дозволяє лише passkey
> (`WebAuthn Passwordless`) або Google SSO. Email/password форму та автоматичний
> redirect до Google вимкнено. Для passkey потрібен раніше зареєстрований
> discoverable credential на пристрої; Google — основна (primary) кнопка,
> passkey — вторинна, бо passkey має не кожен.
>
> **Реєстрація passkey опційна (2026-07-23):**
> `webauthn-register-passwordless` має `defaultAction: false`, тож новий
> користувач після Google SSO потрапляє одразу в застосунок і додає passkey
> добровільно через Account Console (підказку про це показує вкладка
> Settings — `passkeyOptionalHint`). Required actions виконуються після
> *будь-якої* успішної автентифікації, незалежно від того, який step у flow
> її забезпечив; при `defaultAction: true` це давало екран реєстрації passkey
> одразу після першого Google-логіну. Required action не проставляється
> заднім числом, тож перемикання `defaultAction` впливає лише на нових
> користувачів.
>
> **Не вимикайте `webauthn-authenticator-passwordless` у browser flow, щоб
> зробити passkey опційним (спроба 2026-07-23, відкочена того ж дня).**
> Опційність задається виключно через `defaultAction: false` на required
> action. Сам execution має лишатися `ALTERNATIVE`, бо саме він рендерить
> сторінку входу (кастомний `webauthn-authenticate.ftl` із кнопками Google
> та Passkey). З `DISABLED` у flow лишаються тільки `auth-cookie` (без сесії
> не спрацьовує) та `identity-provider-redirector` (без `defaultProvider` не
> робить нічого) — жоден execution не може автентифікувати, і Keycloak падає
> з `AuthenticationFlowException` → `error="invalid_user_credentials"`,
> `userId="null"`, а користувач бачить "We are sorry... Invalid username or
> password" ще до будь-якого вводу. Користувач без passkey нічого не ламає:
> він просто натискає кнопку Google на тій самій сторінці.
>
> **"Cannot login, credential setup required" при додаванні passkey — виправлено
> (2026-07-23).** Account Console → Signing in → Set up passkey запускає
> application-initiated action (`kc_action=webauthn-register-passwordless`), а вона
> **примусово переавтентифіковує**: SSO-cookie ігнорується. Далі у
> `browser-passwordless` не лишається кроку, який може автентифікувати цього
> користувача: `identity-provider-redirector` без `defaultProvider` — no-op, а
> `webauthn-authenticator-passwordless` пропускається, бо юзер уже відомий і
> passkey у нього ще немає (він саме його й додає). Flow падає з
> `AuthenticationFlowException: authenticator: webauthn-authenticator-passwordless`
> → `error="invalid_user_credentials"` і сторінкою "Unexpected error when handling
> authentication request to identity provider. Cannot login, credential setup required."
>
> Рішення — **окремий browser flow `browser-google-reauth`** (є в
> `realm-export.json`): `auth-cookie` + `identity-provider-redirector` з
> `defaultProvider=google`, прив'язаний **лише до клієнта `account-console`**
> через client-level authentication flow override
> (`./keycloak/bind-account-console-flow.sh`). При AIA cookie обходиться →
> redirector веде на Google → після повернення відпрацьовує required action і
> з'являється екран реєстрації passkey. Звичайний вхід у застосунок
> (`kse-pm-web`) не змінився: та сама сторінка з кнопками Passkey і Google.
>
> **Перевірені глухі кути (не повторювати):**
> 1. `defaultProvider=google` на redirector'і у **realm-wide** `browser-passwordless`
>    авто-редіректить **кожен** вхід на Google — сторінка з passkey не рендериться
>    взагалі. Перевірено в обох позиціях: і до, і після webauthn-кроку (позиція не
>    має значення).
> 2. CONDITIONAL-підпотік `Condition - user configured` + webauthn, з
>    `identity-provider-redirector` як ALTERNATIVE-сусідом: Keycloak пише
>    `REQUIRED and ALTERNATIVE elements at same level! Those alternative executions
>    will be ignored`, а сама умова падає з `NullPointerException: Cannot invoke
>    "UserModel.credentialManager()" because "user" is null` на звичайному вході, де
>    користувач ще невідомий (та сама причина, що й у відкоченій post-broker-login
>    спробі нижче).
> 3. Клієнт `account-console` **не можна** описати в `realm-export.json`: Keycloak
>    створює дефолтні клієнти сам, тож імпорт падає з `Duplicate resource error`
>    (`CLIENT(REALM_ID, CLIENT_ID)` unique violation). Тому прив'язка — скриптом.

> **Спроба зробити passkey 2FA на кожному вході — відкочена (2026-07-21).**
> Пробували `postBrokerLoginFlowAlias` на Google IdP з conditional subflow
> (`Condition - user configured` → `WebAuthn Passwordless Authenticator`,
> щоб вимагати passkey лише в тих, хто вже його зареєстрував). **Зламало
> створення нових акаунтів**: під час першого логіну нового користувача
> (коли ще навіть просить Last Name у "First Broker Login" — Google-профіль
> без прізвища) `postBrokerLoginGet`/`brokerLoginFlow` виконується з
> `userId="null"` — локального Keycloak-юзера ще не існує на цьому етапі,
> тож `Condition - user configured` не може коректно визначити "немає
> credential" і НЕ скіпає subflow; далі `webauthn-authenticator-passwordless`
> падає з `AuthenticationFlowException` → те саме "Cannot login, credential
> setup required", але тепер для НОВИХ акаунтів під час створення. Підтверджено
> живими логами Keycloak (`IDENTITY_PROVIDER_POST_LOGIN_ERROR`,
> `error="invalid_user_credentials"`, `userId="null"`). Post Broker Login Flow
> у Keycloak 26 виконується до завершення First Broker Login (лінкування/
> створення юзера), тому будь-яка умова, що читає credential-стан
> користувача, там ненадійна для щойно створених акаунтів. `postBrokerLoginFlowAlias`
> знято з Google IdP, flow `post-broker-passkey`/`passkey-if-configured`
> видалені. Passkey зараз перевіряється **лише** через required action при
> першому вході (реєстрація), не як повторна 2FA-перевірка на кожному
> наступному вході — цього наразі свідомо не робимо, доки не знайдеться
> надійніший механізм (можливий напрямок: власний Keycloak SPI/authenticator
> замість вбудованого `conditional-user-configured`, що явно перевіряє
> `context.getUser() != null` перед оцінкою умови).

> `realm-export.json` створює базовий realm, але не містить кастомного Browser
> flow. Імпорт також не оновлює realm, який уже існує. Тому ці кроки потрібно
> виконати у **кожному** запущеному Keycloak realm `kse-pm` вручну.

> **Обов'язковий крок після імпорту (і для вже наявних realm):**
>
> ```bash
> ./keycloak/bind-account-console-flow.sh            # localhost:8081, realm kse-pm, admin/admin
> ./keycloak/bind-account-console-flow.sh https://kc.example.org kse-pm admin "$KEYCLOAK_ADMIN_PASSWORD"
> ```
>
> Прив'язує flow `browser-google-reauth` до клієнта `account-console`. Без цього
> "Set up passkey" падає з "Cannot login, credential setup required" (див. вище).
> Скрипт ідемпотентний.

У Keycloak Admin Console, realm `kse-pm`:

1. **Authentication → Flows** → скопіюйте `browser` flow → у копії після
   Username/Password (у нашому випадку — після Identity Provider Redirector)
   додайте step **WebAuthn Authenticator** з requirement `Required` →
   У списку flow відкрийте **Action menu** (`⋮`) біля нового flow → **Bind flow** →
   у полі **Browser Flow** виберіть цей flow і натисніть **Save**. У Keycloak 26
   це не окрема вкладка `Bindings`.
2. **Authentication → Required actions** → увімкніть **Webauthn Register
   Passwordless** і позначте `Default action` — кожен новий користувач
   реєструє passkey одразу після першого входу через Google SSO, перш ніж
   потрапити в застосунок. `realm-export.json` вже імпортує це так
   (`"enabled": true, "defaultAction": true`). Наявні користувачі, що
   логінились ще до цього, нічого в черзі не мають (required action не
   проставляється заднім числом) — вони реєструють passkey добровільно
   через Account Console (`Signing in → Set up passkey`). Посилання на
   Account Console (`{keycloakUrl}/realms/{realm}/account/`) не треба шукати
   вручну — воно в топбарі застосунку ("Account Console") і в Налаштуваннях
   ("Відкрити Account Console"), обидва читають адресу з `/api/config`.
3. **Authentication → Policies → WebAuthn Policy**: Relying Party Name —
   `KSE Password Manager`, User Verification Requirement — `preferred`.
4. Fallback: **Recovery Authentication Code (recovery codes)** як альтернативний
   step у тому ж flow, або admin reset — Users → Credentials → видалити passkey.

Біометрія (Touch ID / Face ID / Windows Hello) залишається на пристрої користувача;
Keycloak/застосунок отримують лише криптографічне підтвердження WebAuthn — сервер
ніколи не "зберігає біометрію". У Account Console користувач може додати або
видалити passkey і налаштувати OTP/2FA, але не редагує самі шаблони біометрії чи
системний PIN: ними керує операційна система або менеджер облікових даних пристрою.

### Live-статус (2026-07-19)

У test-realm створено `browser-webauthn` (копія `browser`) з **WebAuthn
Authenticator** requirement `Required` усередині forms subflow після
Username/Password; `Webauthn Register` увімкнений як default required action.
Реєстрація passkey пройшла в headless Chromium через CDP virtual authenticator,
а наступний вхід доходить до Keycloak-екрана **Passkey login** з зареєстрованим
credential. Автоматизована відповідь assertion цим virtual authenticator ще не
завершилась, тому повний повторний вхід і ручні перевірки Touch ID/Windows Hello/
Safari лишаються обов’язковими перед production rollout.

**Тест-матриця MVP:** Chrome (macOS/Windows), Safari (macOS Touch ID), Windows Hello (Edge/Chrome).

**Обмеження MVP:** один passkey на користувача достатньо; синхронізація passkeys
між пристроями — через платформу (iCloud Keychain / Google Password Manager).

## Запуск застосунку проти Keycloak

```bash
docker compose up -d
mvn spring-boot:run          # профіль за замовчуванням: PostgreSQL + JWT
```

Без Keycloak (локальна розробка):

```bash
mvn spring-boot:run -Dspring-boot.run.profiles=dev   # H2 + X-Dev-User headers
```

## Collections: read-only group suggestions

Групи для Collections більше **не** читаються з Keycloak. Джерело — Google
Workspace Directory API (`CollectionGroupService` → `WorkspaceDirectoryClient`);
клієнт `kse-pm-admin`, змінна `KEYCLOAK_ADMIN_CLIENT_SECRET` і
`KeycloakAdminClient` видалені. Keycloak лишається виключно OIDC-брокером входу.

Це **лише UX-підказка**: manager все одно явно вибирає email-и, а браузер
обгортає collection key публічним ключем кожного вибраного користувача. Отже,
членство в Google-групі не надає E2E-доступу автоматично.

## Login/logout audit events: потрібен provider

Висновок для образу `quay.io/keycloak/keycloak:26.0`: вбудована Event Listener SPI є,
але в стандартній дистрибуції немає готового HTTP/webhook event listener, який можна
просто увімкнути в realm. Офіційна документація описує Event Listener як SPI, а для
додаткових provider-ів — розгортання JAR у `providers/` і `kc.sh build`; тому HTTP
доставку не слід вважати функцією "з коробки". Див. [Keycloak Server Developer
Guide](https://www.keycloak.org/docs/latest/server_development/#_events) та
[provider deployment](https://www.keycloak.org/server/configuration-provider).

Для live-середовища оберіть сумісний з Keycloak 26.x, перевірений security-review
сторонній HTTP event listener або напишіть невеликий власний `EventListenerProvider`
SPI. Власний SPI тут навмисно не додано без тесту на реальному Keycloak. Він має:

1. Відправляти тільки `LOGIN`, `LOGIN_ERROR`, `LOGOUT` після commit події на
   `http://app:8080/api/audit/keycloak-events` (не через nginx).
2. Додавати header `X-Keycloak-Events-Secret` зі значенням `KEYCLOAK_EVENTS_SECRET`.
3. Надсилати контракт endpoint-а: `{"type":"LOGIN","email":"user@kse.org.ua","details":"..."}`.
   Стандартна Keycloak event-модель містить ID користувача, тож provider має безпечно
   розв’язати його в email перед відправкою; endpoint навмисно не приймає довільний
   user ID як actor email.
4. Після встановлення provider JAR у `/opt/keycloak/providers/` виконати
   `kc.sh build`, перезапустити Keycloak, а в **Realm settings → Events → Config**
   увімкнути Save events, додати provider до Event listeners і вибрати ці три типи.

`nginx/nginx.conf` повертає `404` для public `/api/audit/keycloak-events`; це
обов’язково зберігає endpoint internal. У `docker-compose.prod.yml` обидва секрети
`KEYCLOAK_EVENTS_SECRET` є обов’язковим.

**Live-статус (2026-07-19):** endpoint перевірено реальними HTTP POST з валідним
shared secret: LOGIN, LOGOUT і шість LOGIN_ERROR збережені, а LOGIN_FAILED
показав brute-force anomaly у UI; неправильний secret повертає 403. Автоматична
доставка від самого Keycloak не перевірена, бо HTTP event-listener provider у
стек не встановлювався.
