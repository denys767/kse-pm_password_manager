-- External shares intentionally contain only an opaque browser-encrypted
-- package. The AES-256 key lives exclusively in the URL fragment.
create table external_shares (
    id                uuid primary key,
    item_id           uuid           not null references password_items (id) on delete cascade,
    owner_email       varchar(255)   not null,
    encrypted_package varchar(65535) not null,
    package_iv        varchar(255)   not null,
    expires_at        timestamptz(6) not null,
    one_time          boolean        not null,
    expired_audited   boolean        not null default false,
    created_at        timestamptz(6) not null
);

create index idx_external_shares_owner_item on external_shares (owner_email, item_id);
