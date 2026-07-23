-- Materialized Google Workspace state. Google remains the source of users,
-- groups and membership; the columns below only store local governance
-- decisions and the last synchronized safe metadata projection.
create table workspace_users (
    email varchar(255) primary key,
    directory_id varchar(255),
    display_name varchar(255) not null,
    google_admin boolean not null,
    role_override varchar(16),
    status varchar(16) not null,
    synced_at timestamptz(6) not null
);
create index idx_workspace_users_status on workspace_users(status);

create table workspace_groups (
    email varchar(255) primary key,
    directory_id varchar(255),
    display_name varchar(255) not null,
    visible_to_users boolean not null default false,
    synced_at timestamptz(6) not null
);

create table workspace_group_memberships (
    id uuid primary key,
    group_email varchar(255) not null references workspace_groups(email) on delete cascade,
    member_email varchar(255) not null,
    synced_at timestamptz(6) not null,
    constraint uq_workspace_group_member unique(group_email, member_email)
);
create index idx_workspace_membership_member on workspace_group_memberships(member_email);

-- Preserve usability of groups already referenced by existing grants. They are
-- seeded without an immutable Google ID and become fully materialized on sync.
insert into workspace_groups (email, display_name, visible_to_users, synced_at)
select distinct lower(grantee), lower(grantee), true, current_timestamp
from permissions where grantee_type = 'GROUP'
on conflict (email) do nothing;

insert into workspace_groups (email, display_name, visible_to_users, synced_at)
select distinct lower(legacy_keycloak_group), legacy_keycloak_group, true, current_timestamp
from collections where legacy_keycloak_group is not null and legacy_keycloak_group like '%@%'
on conflict (email) do nothing;
