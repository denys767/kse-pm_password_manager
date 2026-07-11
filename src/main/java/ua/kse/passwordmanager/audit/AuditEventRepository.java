package ua.kse.passwordmanager.audit;

import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    List<AuditEvent> findByOrderByOccurredAtDescIdDesc(Pageable pageable);
}
