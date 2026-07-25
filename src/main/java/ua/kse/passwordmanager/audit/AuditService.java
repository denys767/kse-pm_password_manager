package ua.kse.passwordmanager.audit;

import java.time.Instant;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

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
        Page<AuditEvent> result = repository.search(from, to, actorEmail, action, itemId,
                PageRequest.of(page, size));
        return new AuditPageDto(result.getContent(), page, size, result.getTotalElements(), result.getTotalPages());
    }
}
