package ua.kse.passwordmanager.audit;

import java.time.Instant;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    List<AuditEvent> findByOrderByOccurredAtDescIdDesc(Pageable pageable);

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
