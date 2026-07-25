package ua.kse.passwordmanager.audit;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    /** Filters are optional; each is skipped when its parameter is null. */
    @Query(value = """
            select e from AuditEvent e
            where (:from is null or e.occurredAt >= :from)
              and (:to is null or e.occurredAt <= :to)
              and (:actorEmail is null or e.actorEmail = :actorEmail)
              and (:action is null or e.action = :action)
              and (:itemId is null or e.itemId = :itemId)
            order by e.occurredAt desc, e.id desc
            """,
            countQuery = """
            select count(e) from AuditEvent e
            where (:from is null or e.occurredAt >= :from)
              and (:to is null or e.occurredAt <= :to)
              and (:actorEmail is null or e.actorEmail = :actorEmail)
              and (:action is null or e.action = :action)
              and (:itemId is null or e.itemId = :itemId)
            """)
    Page<AuditEvent> search(@Param("from") Instant from, @Param("to") Instant to,
                             @Param("actorEmail") String actorEmail, @Param("action") AuditAction action,
                             @Param("itemId") UUID itemId, Pageable pageable);

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
