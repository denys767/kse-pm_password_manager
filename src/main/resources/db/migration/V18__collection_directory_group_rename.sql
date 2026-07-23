-- Collections groups come from Google Workspace, not Keycloak (see V11/V14).
-- The column and the vestigial allowlist table still carried the old name.
alter table collections rename column keycloak_group to directory_group;

-- CollectionGroupService no longer keeps a local allowlist: Google owns the
-- group list, and the admin allow/disallow endpoints were no-ops.
drop table if exists allowed_keycloak_groups;
