-- Google Workspace Directory is now the source of group membership.  Keep
-- direct user shares intact, but never let legacy Keycloak group rows grant
-- access after this migration.
alter table permissions add column if not exists directory_subject_id varchar(255);
alter table permissions add column if not exists directory_display_name varchar(255);
alter table permissions add column if not exists status varchar(32) not null default 'ACTIVE';

update permissions set status = 'RELINK_REQUIRED' where grantee_type = 'GROUP';

create table permission_members (
    id uuid primary key,
    permission_id uuid not null references permissions(id) on delete cascade,
    member_email varchar(255) not null,
    status varchar(32) not null,
    created_at timestamptz(6) not null,
    constraint uq_permission_member unique (permission_id, member_email)
);
create index idx_permission_members_email_status on permission_members(member_email, status);

-- Old Keycloak-managed collections are deliberately detached. Existing
-- collection_members remain explicit legacy members, so no wrapped key is lost.
alter table collections add column if not exists legacy_keycloak_group varchar(255);
update collections set legacy_keycloak_group = keycloak_group where keycloak_group is not null;
update collections set keycloak_group = null where keycloak_group is not null;
