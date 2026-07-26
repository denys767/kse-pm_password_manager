package ua.kse.passwordmanager.directory;

import java.time.Instant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Schedules {@link WorkspaceDirectorySnapshotWriter} and records why a pass
 * failed. Holds no transaction of its own: the snapshot swap belongs to the
 * writer, reached through its Spring proxy so {@code @Transactional} actually
 * applies.
 */
@Service
public class WorkspaceDirectorySyncService {
    private static final Logger log = LoggerFactory.getLogger(WorkspaceDirectorySyncService.class);
    private final WorkspaceDirectorySnapshotWriter writer;
    private final WorkspaceUserRepository users;
    private volatile Instant lastSuccessAt;
    private volatile Instant lastAttemptAt;
    private volatile String lastError;
    private volatile int consecutiveFailures;

    public WorkspaceDirectorySyncService(WorkspaceDirectorySnapshotWriter writer, WorkspaceUserRepository users) {
        this.writer = writer;
        this.users = users;
    }

    /** Runs every 15 minutes. The unavailable client deliberately does no work
     * in installations that have not mounted Directory credentials yet. */
    @Scheduled(fixedDelayString = "${pm.google-workspace.sync-interval-ms:900000}",
            initialDelayString = "${pm.google-workspace.sync-initial-delay-ms:120000}")
    public void scheduledSync() {
        syncQuietly();
    }

    /**
     * Until the very first snapshot lands, retries every minute instead of
     * every fifteen. A Directory outage (or expired caller credentials) during
     * startup used to leave the whole deployment with an empty snapshot — and
     * therefore every request denied — for a quarter of an hour after the
     * problem was fixed.
     */
    @Scheduled(fixedDelayString = "${pm.google-workspace.bootstrap-retry-ms:60000}",
            initialDelayString = "${pm.google-workspace.bootstrap-initial-delay-ms:5000}")
    public void bootstrapSync() {
        if (lastSuccessAt != null || users.count() > 0) return;
        log.info("Workspace snapshot is empty; attempting an initial directory sync");
        syncQuietly();
    }

    /**
     * An administrator asking for a sync right now. Unlike the scheduled
     * passes this one lets the failure out — the admin is watching, and a
     * button that reports success while nothing synced is worse than an error.
     * The outcome still lands in {@link #status()} either way.
     */
    public WorkspaceDirectorySnapshotWriter.SyncResult syncNow() {
        lastAttemptAt = Instant.now();
        try {
            WorkspaceDirectorySnapshotWriter.SyncResult result = writer.sync();
            lastSuccessAt = Instant.now();
            lastError = null;
            consecutiveFailures = 0;
            return result;
        } catch (RuntimeException e) {
            consecutiveFailures++;
            lastError = rootCauseMessage(e);
            throw e;
        }
    }

    /** Never lets a Directory problem escape into the scheduler: local
     * governance state is left exactly as it was, and the failure is recorded
     * for {@link #status()} so an administrator can see why data is stale. */
    private void syncQuietly() {
        lastAttemptAt = Instant.now();
        try {
            WorkspaceDirectorySnapshotWriter.SyncResult result = writer.sync();
            lastSuccessAt = Instant.now();
            lastError = null;
            consecutiveFailures = 0;
            log.info("Workspace directory sync: {} users, {} groups, {} memberships",
                    result.users(), result.groups(), result.memberships());
        } catch (RuntimeException e) {
            // Swallowed so a Directory outage never wipes local governance state,
            // but never silently: without this line a misconfigured deployment
            // just looks like "users are not provisioned" with no trace at all.
            consecutiveFailures++;
            lastError = rootCauseMessage(e);
            log.warn("Workspace directory sync failed ({} in a row); local governance state left unchanged: {}",
                    consecutiveFailures, lastError, e);
        }
    }

    /** Freshness of the local Workspace snapshot, for the admin screen. */
    public DirectoryStatus status() {
        return new DirectoryStatus(lastSuccessAt, lastAttemptAt, lastError, consecutiveFailures, users.count());
    }

    private static String rootCauseMessage(Throwable failure) {
        Throwable cause = failure;
        while (cause.getCause() != null && cause.getCause() != cause) cause = cause.getCause();
        return cause.getMessage() == null ? cause.getClass().getSimpleName() : cause.getMessage();
    }

    /** Null timestamps mean "never": a snapshot that has never been fetched is
     * the state that used to lock every user out of the application. */
    public record DirectoryStatus(Instant lastSuccessAt, Instant lastAttemptAt, String lastError,
                                  int consecutiveFailures, long knownUsers) {}
}
