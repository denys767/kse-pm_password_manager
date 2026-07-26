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
 * Routes directory reads between live Google and the materialized snapshot.
 *
 * <p>Interactive lookups — autocomplete and share validation — are answered
 * from the snapshot, and only reach Google when the snapshot has nothing to
 * say (a cold start before the synchronizer's first pass). Going to Google per
 * keystroke instead meant five Directory API calls per request, authenticated
 * as the Workspace admin and driven by any signed-in user: enough to exhaust
 * the per-customer quota and take sharing down for everyone, and enough to
 * couple a type-ahead to Google's latency and availability for no benefit. The
 * snapshot holds the same data the synchronizer already wrote; serving it is
 * not a weaker answer, only a slightly older one.
 *
 * <p>{@code memberEmails} and the synchronizer's own projections still go
 * straight to Google, falling back only on failure, so a degraded read can
 * never be written back as if it were fresh Directory data.
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
        List<DirectoryPrincipal> materialized = snapshot.search(query, types, limit);
        if (!materialized.isEmpty()) return materialized;
        // Empty can mean either "no such person" or "the snapshot has not been
        // built yet". Only the second is worth a Google call, and asking is
        // cheap precisely because it is rare; a genuine miss costs one lookup
        // that also returns nothing.
        return withFallback("search", () -> live.search(query, types, limit), List::of);
    }

    @Override
    public Optional<DirectoryPrincipal> find(DirectoryPrincipal.Type type, String id) {
        Optional<DirectoryPrincipal> materialized = snapshot.find(type, id);
        if (materialized.isPresent()) return materialized;
        return withFallback("find", () -> live.find(type, id), Optional::empty);
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
