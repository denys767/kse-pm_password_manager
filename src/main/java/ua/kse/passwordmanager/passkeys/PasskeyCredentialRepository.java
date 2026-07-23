package ua.kse.passwordmanager.passkeys;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface PasskeyCredentialRepository extends JpaRepository<PasskeyCredential, UUID> {
    List<PasskeyCredential> findByRelyingPartyId(String relyingPartyId);
    List<PasskeyCredential> findByItemIdIn(java.util.Collection<UUID> itemIds);
    Optional<PasskeyCredential> findByCredentialId(String credentialId);
    @Modifying
    @Query("update PasskeyCredential c set c.signCounter = :counter where c.id = :id and c.signCounter < :counter")
    int advanceCounter(@Param("id") UUID id, @Param("counter") long counter);
}
