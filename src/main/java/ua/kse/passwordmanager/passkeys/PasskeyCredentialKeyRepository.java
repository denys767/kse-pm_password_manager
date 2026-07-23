package ua.kse.passwordmanager.passkeys;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PasskeyCredentialKeyRepository extends JpaRepository<PasskeyCredentialKey, UUID> {
    Optional<PasskeyCredentialKey> findByCredentialIdAndUserEmail(UUID credentialId, String userEmail);
    void deleteByUserEmail(String userEmail);
}
