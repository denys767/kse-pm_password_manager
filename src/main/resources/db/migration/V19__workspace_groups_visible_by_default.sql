-- New groups are now visible by default; only the column default changes.
-- Existing rows keep whatever visibility an administrator already set.
alter table workspace_groups alter column visible_to_users set default true;
