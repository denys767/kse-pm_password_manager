create table item_attachments (
    id uuid primary key,
    item_id uuid not null unique references password_items(id) on delete cascade,
    drive_file_id varchar(255) not null,
    encrypted_filename varchar(4096) not null,
    encrypted_filename_iv varchar(255) not null,
    mime_type varchar(255) not null,
    ciphertext_size bigint not null,
    ciphertext_sha256 varchar(64) not null,
    nonce varchar(255) not null,
    wrapped_file_key varchar(4096) not null,
    wrapped_file_key_iv varchar(255) not null,
    created_at timestamp with time zone not null,
    updated_at timestamp with time zone not null
);
