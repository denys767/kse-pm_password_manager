-- Defensive backfill: on environments where the V6->V7 migration rename
-- (06ba332) landed after this database's history already recorded a
-- different script under version 6/7, Flyway's checksum/order validation
-- can leave "type" missing even though later migrations (V8+) applied
-- fine. This is idempotent and safe to run whether or not V7 succeeded.
alter table password_items add column if not exists type varchar(32) not null default 'LOGIN';
