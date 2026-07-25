package ua.kse.passwordmanager.audit;

import jakarta.persistence.criteria.Predicate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class AuditService {

    private final AuditEventRepository repository;

    public AuditService(AuditEventRepository repository) {
        this.repository = repository;
    }

    public void record(String actorEmail, AuditAction action, UUID itemId, String itemName,
                       String target, String details) {
        repository.save(new AuditEvent(actorEmail, action, itemId, itemName, target, details));
    }

    public AuditPageDto search(int page, int size, Instant from, Instant to, String actorEmail,
                                AuditAction action, UUID itemId) {
        PageRequest pageRequest = PageRequest.of(page, size,
                Sort.by(Sort.Order.desc("occurredAt"), Sort.Order.desc("id")));
        Page<AuditEvent> result =
                repository.findAll(filter(from, to, actorEmail, action, itemId), pageRequest);
        return new AuditPageDto(result.getContent(), page, size, result.getTotalElements(), result.getTotalPages());
    }

    /** Each filter contributes a predicate only when supplied, so absent ones never reach the DB. */
    private static Specification<AuditEvent> filter(Instant from, Instant to, String actorEmail,
                                                    AuditAction action, UUID itemId) {
        return (root, query, cb) -> {
            List<Predicate> predicates = new ArrayList<>();
            if (from != null) {
                predicates.add(cb.greaterThanOrEqualTo(root.get("occurredAt"), from));
            }
            if (to != null) {
                predicates.add(cb.lessThanOrEqualTo(root.get("occurredAt"), to));
            }
            if (StringUtils.hasText(actorEmail)) {
                predicates.add(cb.equal(root.get("actorEmail"), actorEmail));
            }
            if (action != null) {
                predicates.add(cb.equal(root.get("action"), action));
            }
            if (itemId != null) {
                predicates.add(cb.equal(root.get("itemId"), itemId));
            }
            return cb.and(predicates.toArray(new Predicate[0]));
        };
    }
}
