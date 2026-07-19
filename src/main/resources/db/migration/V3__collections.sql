-- Collections (org-key model): each collection has its own AES key, stored
-- only wrapped — RSA-OAEP per member (collection_members.wrapped_key), while
-- item keys of collection records are wrapped with the collection key on the
-- item row itself.

create table collections (
    id          uuid primary key,
    name        varchar(255)   not null,
    owner_email varchar(255)   not null,
    created_at  timestamptz(6) not null,
    updated_at  timestamptz(6) not null
);

create table collection_members (
    id            uuid primary key,
    collection_id uuid           not null references collections (id),
    member_email  varchar(255)   not null,
    role          varchar(255)   not null,
    wrapped_key   varchar(4096)  not null,
    added_by      varchar(255)   not null,
    created_at    timestamptz(6) not null,
    constraint uq_collection_members unique (collection_id, member_email)
);

create index idx_collection_members_email on collection_members (member_email);

alter table password_items add column collection_id uuid references collections (id);
alter table password_items add column collection_wrapped_key varchar(4096);
alter table password_items add column collection_wrapped_key_iv varchar(255);

create index idx_password_items_collection on password_items (collection_id);
