package ua.kse.passwordmanager.directory;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ua.kse.passwordmanager.common.BadGatewayException;

/**
 * Keeps the interactive directory usable when Google is not.
 *
 * <p>Autocomplete and share validation fall back to the materialized snapshot;
 * the synchronizer's own projections never do, so a fallback read can never be
 * written back as if it were fresh Directory data.
 */
public class ResilientWorkspaceDirectoryClient implements WorkspaceDirectoryClient {

    private static final Logger log = LoggerFactory.getLogger(ResilientWorkspaceDirectoryClient.class);
    private static final long LOG_INTERVAL_MS = 60_000;

    private final WorkspaceDirectoryClient live;
    private final WorkspaceDirectoryClient snapshot;
    private final AtomicLong lastLoggedAt = new AtomicLong();
    private volatile Instant servingFromSnapshotSince;

    public ResilientWorkspaceDirectoryClient(WorkspaceDirectoryClient live, WorkspaceDirectoryClient snapshot) {
        this.live = live;
        this.snapshot = snapshot;
    }

    /** Null while Google is answering; set to the moment the first degraded
     * read happened, so the admin screen can say how long this has been true. */
    public Instant servingFromSnapshotSince() {
        return servingFromSnapshotSince;
    }

    @Override
    public List<DirectoryPrincipal> search(String query, List<DirectoryPrincipal.Type> types, int limit) {
        return withFallback("search", () -> live.search(query, types, limit), () -> snapshot.search(query, types, limit));
    }

    @Override
    public Optional<DirectoryPrincipal> find(DirectoryPrincipal.Type type, String id) {
        return withFallback("find", () -> live.find(type, id), () -> snapshot.find(type, id));
    }

    @Override
    public List<String> memberEmails(String groupId) {
        return withFallback("memberEmails", () -> live.memberEmails(groupId), () -> snapshot.memberEmails(groupId));
    }

    private <T> T withFallback(String operation, Supplier<T> primary, Supplier<T> secondary) {
        try {
            T answer = primary.get();
            servingFromSnapshotSince = null;
            return answer;
        } catch (BadGatewayException e) {
            if (servingFromSnapshotSince == null) servingFromSnapshotSince = Instant.now();
            long now = System.currentTimeMillis();
            long last = lastLoggedAt.get();
            if (now - last > LOG_INTERVAL_MS && lastLoggedAt.compareAndSet(last, now)) {
                log.warn("Google Workspace Directory is unavailable ({}); answering {} from the local snapshot, "
                        + "which was last refreshed by the directory sync", e.getMessage(), operation);
            }
            return secondary.get();
        }
    }

    // The synchronizer's projections: a snapshot answer here would be the
    // snapshot syncing with itself, and would reset the sync's freshness.
    @Override public List<DirectoryUser> listUsers() { return live.listUsers(); }
    @Override public List<DirectoryGroup> listGroups() { return live.listGroups(); }
    @Override public Optional<String> userPhotoDataUrl(String userKey) { return live.userPhotoDataUrl(userKey); }

    @Override public DirectoryCredentialSummary credentials() { return live.credentials(); }
}
