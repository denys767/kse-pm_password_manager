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
2. У Keycloak Admin Console → realm `kse-pm` → Identity providers → google —
   вставте отримані Client ID / Client Secret (в realm-export.json це плейсхолдери
   `REPLACE_WITH_GOOGLE_CLIENT_ID/SECRET`).
3. `hostedDomain: kse.org.ua` обмежує вхід корпоративними акаунтами.
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

> **Поточний стан входу (2026-07-21):** `browser-passwordless forms` (username
> + REQUIRED WebAuthn, без жодного fallback) лишається вимкненим (`DISABLED`) як
> top-level execution — цей username-крок дав глухий кут "We are sorry... Cannot
> login, credential setup required" для будь-кого без passkey, тож єдиний шлях
> входу — **Google SSO** (`identity-provider-redirector` з `authenticatorConfig`
> `google-auto-redirect`, логін-сторінка одразу редіректить на Google).
>
> **Реєстрація passkey знову обов'язкова для нових користувачів**
> (`webauthn-register-passwordless`: `defaultAction: true`). Required actions в
> Keycloak виконуються одразу після *будь-якої* успішної автентифікації,
> незалежно від того, який step у flow її забезпечив — тобто після першого
> входу через Google SSO новий користувач одразу отримує екран реєстрації
> passkey, перш ніж потрапити в застосунок. Це не залежить від того, що
> username+webauthn-форма для логіну вимкнена: required action — окремий
> механізм, що спрацьовує вже після успішної Google-автентифікації.
> Наявні користувачі, що вже логінились раніше (коли `defaultAction` був
> `false`), нічого в черзі не мають і passkey реєструють лише добровільно
> через Account Console — required action не проставляється заднім числом.
>
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
ніколи не "зберігає біометрію".

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

`realm-export.json` містить confidential client `kse-pm-admin` з увімкненим
service account і єдиною роллю `realm-management:view-users`. Перед імпортом/першим
запуском замініть його `secret` плейсхолдер або після імпорту згенеруйте Client secret
у **Clients → kse-pm-admin → Credentials** і передайте те саме значення застосунку:

```bash
export KEYCLOAK_ADMIN_CLIENT_SECRET='...'
```

Backend отримує access token через `client_credentials`, шукає group і читає її
members через Admin REST API. Це **лише UX-підказка**: manager все одно явно вибирає
email-и, а браузер обгортає collection key публічним ключем кожного вибраного
користувача. Отже, додавання до Keycloak group не надає E2E-доступу автоматично.

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
`KEYCLOAK_ADMIN_CLIENT_SECRET` та `KEYCLOAK_EVENTS_SECRET` є обов’язковими.

**Live-статус (2026-07-19):** endpoint перевірено реальними HTTP POST з валідним
shared secret: LOGIN, LOGOUT і шість LOGIN_ERROR збережені, а LOGIN_FAILED
показав brute-force anomaly у UI; неправильний secret повертає 403. Автоматична
доставка від самого Keycloak не перевірена, бо HTTP event-listener provider у
стек не встановлювався.
