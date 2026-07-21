-- Template discriminator only. Sensitive template fields stay inside the
-- existing client-encrypted payload (encrypted_notes), never in columns.
alter table password_items add column type varchar(32) not null default 'LOGIN';
