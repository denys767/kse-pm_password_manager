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

У Keycloak Admin Console, realm `kse-pm`:

1. **Authentication → Flows** → скопіюйте `browser` flow → у копії після
   Username/Password (у нашому випадку — після Identity Provider Redirector)
   додайте step **WebAuthn Authenticator** з requirement `Required` →
   Bind flow як Browser flow.
2. **Authentication → Required actions** → увімкніть **Webauthn Register**
   і позначте `Default action`, щоб кожен новий користувач реєстрував passkey
   при першому вході.
3. **Authentication → Policies → WebAuthn Policy**: Relying Party Name —
   `KSE Password Manager`, User Verification Requirement — `preferred`.
4. Fallback: **Recovery Authentication Code (recovery codes)** як альтернативний
   step у тому ж flow, або admin reset — Users → Credentials → видалити passkey.

Біометрія (Touch ID / Face ID / Windows Hello) залишається на пристрої користувача;
Keycloak/застосунок отримують лише криптографічне підтвердження WebAuthn — сервер
ніколи не "зберігає біометрію".

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
