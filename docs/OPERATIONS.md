# Operations: бекапи, відновлення, моніторинг

## Бекапи PostgreSQL

Дані у БД зашифровані на клієнті (сервер зберігає лише ciphertext і wrapped keys),
тому бекап БД **не розкриває паролі** — але його втрата означає втрату vault-ів,
які неможливо відновити без даних. Бекапи критичні.

Щоденний дамп (cron на хості):

```bash
docker compose -f docker-compose.prod.yml exec -T postgres \
  pg_dump -U pm -Fc pm > backups/pm-$(date +%F).dump
find backups/ -name 'pm-*.dump' -mtime +30 -delete
```

Рекомендації:
- Зберігати копії поза хостом (object storage з версіонуванням).
- Бекапити також realm Keycloak: `kc.sh export` або дамп його БД
  (у поточному compose Keycloak використовує вбудовану dev-БД — для проду
  переведіть його на PostgreSQL).
- Раз на місяць проводити тестове відновлення (див. runbook нижче).

## Runbook: відновлення

1. Підняти чистий стек без застосунку: `docker compose -f docker-compose.prod.yml up -d postgres keycloak`.
2. Відновити дамп:
   ```bash
   docker compose -f docker-compose.prod.yml exec -T postgres \
     pg_restore -U pm -d pm --clean --if-exists < backups/pm-YYYY-MM-DD.dump
   ```
3. Запустити застосунок: `docker compose -f docker-compose.prod.yml up -d app nginx`.
   Flyway звірить версію схеми; Hibernate — відповідність моделі (`ddl-auto: validate`).
4. Перевірити: `curl -k https://host/api/health` → `{"status":"UP"}`; вхід користувача;
   розшифрування одного запису (ключі користувачів зберігаються в БД у зашифрованому
   вигляді, тож після відновлення passphrase користувачів працюють як раніше).

**Що НЕ відновлюється з серверного бекапу:** local-only записи (вони живуть лише
в браузерах користувачів — це задокументована властивість) і passphrase користувачів
(zero-knowledge: якщо користувач забув passphrase — записи втрачені, адмін може лише
скинути keypair через `PUT /api/keys/me?force=true`, після чого старі записи стають
нечитабельними).

## Моніторинг

- Метрики: `/actuator/prometheus` (доступний лише з внутрішньої мережі; nginx закриває
  `/actuator/*` ззовні, крім health).
- Мінімальний набір алертів для Prometheus:
  - `up == 0` (застосунок недоступний);
  - `rate(http_server_requests_seconds_count{status="5xx"}[5m]) > 0.1`;
  - `rate(http_server_requests_seconds_count{status="429"}[5m])` — сплеск rate limiting
    (можливий brute-force);
  - `hikaricp_connections_pending > 0` тривалий час — вичерпання пулу БД.
- Аномалії в audit log (сплески `ITEM_COPIED`/`ACCESS_REVOKED`/`ITEM_SHARED` по одному
  користувачу) — поки ручна перевірка через `/api/audit`; автоматичні алерти заплановано
  (див. [ROADMAP.md](ROADMAP.md), Фаза 4).

## Чекліст перед запуском у прод

- [ ] Реальні TLS-сертифікати замість self-signed у `nginx/certs/`.
- [ ] Змінені всі паролі за замовчуванням (`DB_PASSWORD`, `KEYCLOAK_ADMIN_PASSWORD`).
- [ ] Keycloak переведений з `start-dev` на `start` з власною PostgreSQL.
- [ ] Google OAuth credentials у realm, `hostedDomain` перевірено.
- [ ] WebAuthn увімкнено як required action ([KEYCLOAK.md](KEYCLOAK.md)).
- [ ] Профіль `dev` не активний; `PM_ALLOW_INSECURE_DEV` не встановлено.
- [ ] Бекапи налаштовані й перевірені відновленням.
- [ ] Зовнішній security review / pentest проведено.
