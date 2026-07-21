-- Small client-resized data: URI (PNG/JPEG), never a secret — shown to any
-- authenticated user viewing this person's collections/shares.
alter table user_settings add column avatar_data_url text;
