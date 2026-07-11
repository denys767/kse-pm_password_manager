package ua.kse.passwordmanager.audit;

import java.util.List;
import java.util.UUID;
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

    public List<AuditEvent> latest(int limit) {
        return repository.findByOrderByOccurredAtDescIdDesc(PageRequest.of(0, limit));
    }
}
