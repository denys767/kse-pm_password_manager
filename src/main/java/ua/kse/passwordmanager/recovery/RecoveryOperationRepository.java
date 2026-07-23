package ua.kse.passwordmanager.recovery;

import java.util.*;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RecoveryOperationRepository extends JpaRepository<RecoveryOperation, UUID> {
    List<RecoveryOperation> findBySubjectEmailOrderByCreatedAtDesc(String subjectEmail);
}
