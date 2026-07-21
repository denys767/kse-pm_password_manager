-- Managed Keycloak groups remain read-only metadata.  A membership row without
-- a wrapped key is deliberately PENDING_PROVISIONING and grants no access.
create table allowed_keycloak_groups (
    group_name varchar(255) primary key,
    created_at timestamptz(6) not null
);

alter table collection_members alter column wrapped_key drop not null;
alter table collection_members add column status varchar(32) not null default 'ACTIVE';
create index idx_collection_members_collection_status on collection_members (collection_id, status);
