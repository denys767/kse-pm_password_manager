package ua.kse.passwordmanager.externalsharing;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import jakarta.persistence.LockModeType;

public interface ExternalShareRepository extends JpaRepository<ExternalShare, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from ExternalShare s join fetch s.item where s.id = :id")
    Optional<ExternalShare> findForPublicRead(@Param("id") UUID id);

    Optional<ExternalShare> findByIdAndOwnerEmail(UUID id, String ownerEmail);
}
