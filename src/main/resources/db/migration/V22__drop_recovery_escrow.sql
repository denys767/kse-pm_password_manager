-- Removes the KMS recovery escrow introduced in V16.  Escrow wrapping meant a
-- service identity could decrypt any enrolled item, collection or passkey; the
-- deployment now keeps key material exclusively under the user passphrase.
-- user_notifications only ever carried recovery-operation messages, and its FK
-- points at recovery_operations, so it goes first.
drop table if exists user_notifications;
drop table if exists recovery_operations;
drop table if exists recovery_key_envelopes;
