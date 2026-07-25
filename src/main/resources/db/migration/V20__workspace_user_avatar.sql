-- Google Workspace profile photos, materialized alongside the rest of the
-- directory snapshot. The etag lets a sync skip re-downloading an unchanged
-- photo; a null etag with a null data URL simply means "not fetched yet".
alter table workspace_users
    add column avatar_data_url text,
    add column avatar_etag     varchar(255);
