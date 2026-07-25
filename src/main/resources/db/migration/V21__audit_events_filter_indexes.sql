-- Audit log paging/filtering by actor, action and target item needs these
-- columns indexed, or a filtered admin query degenerates into a full table
-- scan as audit_events grows unbounded. (occurred_at is already indexed by
-- V1 baseline's idx_audit_events_occurred.)
create index if not exists idx_audit_events_actor_email on audit_events (actor_email);
create index if not exists idx_audit_events_action on audit_events (action);
create index if not exists idx_audit_events_item_id on audit_events (item_id);
