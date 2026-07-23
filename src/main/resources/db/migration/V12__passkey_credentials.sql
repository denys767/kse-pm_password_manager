create table passkey_credentials (
    id uuid primary key,
    item_id uuid not null references password_items(id) on delete cascade,
    owner_email varchar(255) not null,
    relying_party_id varchar(253) not null,
    credential_id varchar(1024) not null unique,
    user_handle varchar(1024) not null,
    algorithm varchar(32) not null,
    public_key varchar(4096) not null,
    encrypted_private_material varchar(16384) not null,
    private_material_iv varchar(255) not null,
    transports varchar(1024),
    sign_counter bigint not null default 0,
    created_at timestamptz(6) not null,
    updated_at timestamptz(6) not null
);
create index idx_passkey_credentials_rp_id on passkey_credentials(relying_party_id);
create table passkey_credential_keys (
    id uuid primary key,
    credential_id uuid not null references passkey_credentials(id) on delete cascade,
    user_email varchar(255) not null,
    wrapped_key varchar(4096) not null,
    created_at timestamptz(6) not null,
    constraint uq_passkey_credential_key unique (credential_id, user_email)
);
