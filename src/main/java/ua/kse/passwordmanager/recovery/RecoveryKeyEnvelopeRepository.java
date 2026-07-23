package ua.kse.passwordmanager.recovery;

import java.util.*;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RecoveryKeyEnvelopeRepository extends JpaRepository<RecoveryKeyEnvelope, UUID> {
    Optional<RecoveryKeyEnvelope> findByResourceTypeAndResourceId(RecoveryResourceType type, UUID resourceId);
    List<RecoveryKeyEnvelope> findByOwnerEmail(String ownerEmail);
    long countByOwnerEmail(String ownerEmail);
}
