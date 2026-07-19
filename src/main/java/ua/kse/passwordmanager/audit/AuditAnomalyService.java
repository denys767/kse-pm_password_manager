package ua.kse.passwordmanager.audit;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Heuristic, threshold-based anomaly detection over the audit log: flags an
 * actor performing an unusually high number of same-type actions in a short
 * window (mass copying, mass revoking, mass sharing) — a common signature of
 * a compromised account or insider misuse. Computed on demand from recent
 * events; no scheduler, no ML — this is a starter signal, not a SIEM
 * replacement (see docs/ROADMAP.md).
 */
@Service
public class AuditAnomalyService {

    /** Actions worth watching, with a lower default threshold for the more
     * sensitive ones (revoking access, removing collection members). */
    private static final Map<AuditAction, Long> DEFAULT_THRESHOLDS = Map.of(
            AuditAction.ITEM_COPIED, 10L,
            AuditAction.ITEM_SHARED, 10L,
            AuditAction.ACCESS_REVOKED, 5L,
            AuditAction.COLLECTION_MEMBER_REMOVED, 5L,
            AuditAction.LOGIN_FAILED, 5L,
            AuditAction.ITEM_VIEWED, 30L);

    private static final long DEFAULT_THRESHOLD = 20L;

    private final AuditEventRepository repository;
    private final int windowMinutes;

    public AuditAnomalyService(AuditEventRepository repository,
                               @Value("${pm.audit.anomaly.window-minutes:15}") int windowMinutes) {
        this.repository = repository;
        this.windowMinutes = windowMinutes;
    }

    public List<AnomalyDto> detect() {
        Instant since = Instant.now().minus(windowMinutes, ChronoUnit.MINUTES);
        return repository.findDistinctActorActionsSince(since).stream()
                .map(pair -> {
                    long threshold = DEFAULT_THRESHOLDS.getOrDefault(pair.getAction(), DEFAULT_THRESHOLD);
                    long count = repository.countByActorEmailAndActionAndOccurredAtGreaterThanEqual(
                            pair.getActorEmail(), pair.getAction(), since);
                    return count > threshold
                            ? new AnomalyDto(pair.getActorEmail(), pair.getAction(), count, windowMinutes, threshold)
                            : null;
                })
                .filter(Objects::nonNull)
                .toList();
    }
}
