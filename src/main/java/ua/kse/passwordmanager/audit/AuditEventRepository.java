package ua.kse.passwordmanager.audit;

import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;

/**
 * Filtered search goes through {@link JpaSpecificationExecutor} rather than a JPQL query with
 * {@code :param is null} guards: those bind an untyped null, which PostgreSQL rejects with
 * "could not determine data type of parameter" (SQLSTATE 42P18).
 */
public interface AuditEventRepository
        extends JpaRepository<AuditEvent, Long>, JpaSpecificationExecutor<AuditEvent> {

    /** Distinct (actor, action) pairs with any activity since {@code since} —
     * the candidate set the anomaly scan then counts precisely. */
    @Query("""
            select distinct e.actorEmail as actorEmail, e.action as action
            from AuditEvent e where e.occurredAt >= :since
            """)
    List<ActorAction> findDistinctActorActionsSince(Instant since);

    long countByActorEmailAndActionAndOccurredAtGreaterThanEqual(
            String actorEmail, AuditAction action, Instant since);

    interface ActorAction {
        String getActorEmail();

        AuditAction getAction();
    }
}
