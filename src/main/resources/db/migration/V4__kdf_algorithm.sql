-- Versions the passphrase-to-KEK derivation algorithm so newly registered
-- keypairs can move to Argon2id (memory-hard, OWASP-recommended) while
-- keypairs registered before this column existed keep unlocking with PBKDF2 —
-- there is no forced migration, since re-deriving a keypair's KEK requires the
-- user's passphrase, which the server never has.

alter table user_keys add column kdf_algorithm varchar(32) not null default 'PBKDF2';
alter table user_keys alter column kdf_algorithm drop default;
