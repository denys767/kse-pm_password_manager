alter table workspace_users add column local_status varchar(16);
update workspace_users set local_status = status where local_status is null;
alter table workspace_users alter column local_status set not null;
alter table workspace_users drop column status;
alter table workspace_users add column google_suspended boolean not null default false;
alter table workspace_users add column directory_present boolean not null default true;
alter table workspace_groups add column directory_present boolean not null default true;
create index idx_workspace_users_local_status on workspace_users(local_status);
