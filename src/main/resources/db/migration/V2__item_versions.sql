-- Version history: a ciphertext snapshot of an item taken before each update,
-- encrypted with the same per-item key as the live record.

create table password_item_versions (
    id                 uuid primary key,
    item_id            uuid           not null references password_items (id),
    name               varchar(255)   not null,
    url                varchar(2048),
    username           varchar(255),
    encrypted_password varchar(4096)  not null,
    password_iv        varchar(255)   not null,
    encrypted_notes    varchar(16384),
    notes_iv           varchar(255),
    replaced_by        varchar(255)   not null,
    replaced_at        timestamptz(6) not null
);

create index idx_item_versions_item on password_item_versions (item_id, replaced_at desc);
