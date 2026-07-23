-- KMS ciphertext only.  No plaintext secret or raw AES key is persisted here.
create table recovery_key_envelopes (
    id uuid primary key,
    resource_type varchar(16) not null,
    resource_id uuid not null,
    owner_email varchar(255) not null,
    key_version varchar(1024) not null,
    ciphertext varchar(8192) not null,
    created_at timestamptz(6) not null,
    updated_at timestamptz(6) not null,
    constraint uq_recovery_resource unique(resource_type, resource_id)
);
create index idx_recovery_envelope_owner on recovery_key_envelopes(owner_email);

create table recovery_operations (
    id uuid primary key,
    operation_type varchar(32) not null,
    status varchar(16) not null,
    actor_email varchar(255) not null,
    subject_email varchar(255) not null,
    successor_email varchar(255),
    reason varchar(1024) not null,
    failure_reason varchar(2048),
    created_at timestamptz(6) not null,
    completed_at timestamptz(6)
);
create index idx_recovery_operation_subject on recovery_operations(subject_email, created_at desc);

create table user_notifications (
    id uuid primary key,
    recipient_email varchar(255) not null,
    notification_type varchar(64) not null,
    message varchar(2048) not null,
    recovery_operation_id uuid references recovery_operations(id) on delete set null,
    created_at timestamptz(6) not null,
    read_at timestamptz(6)
);
create index idx_user_notifications_recipient on user_notifications(recipient_email, created_at desc);
