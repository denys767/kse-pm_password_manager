package ua.kse.passwordmanager.passkeys;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface PasskeyCredentialKeyRepository extends JpaRepository<PasskeyCredentialKey, UUID> {
    Optional<PasskeyCredentialKey> findByCredentialIdAndUserEmail(UUID credentialId, String userEmail);
    void deleteByUserEmail(String userEmail);

    /** Every wrapped key held for a set of credentials, so the distribution
     * endpoint can work out who is still missing one without a query per
     * credential. */
    List<PasskeyCredentialKey> findByCredentialIdIn(java.util.Collection<UUID> credentialIds);

    /**
     * Drops a grantee's wrapped keys for every passkey on one item. Called when
     * a grant is revoked or moves to a role that may not use passkeys: the
     * access check in PasskeyService already refuses to hand the credential
     * back, so this is not what stops them — it removes key material that has
     * no reason to exist, and that a later re-grant would otherwise silently
     * bring back to life.
     */
    @Modifying
    @Transactional
    @Query("delete from PasskeyCredentialKey k where k.userEmail = :userEmail "
            + "and k.credential.id in (select c.id from PasskeyCredential c where c.itemId = :itemId)")
    void deleteByItemIdAndUserEmail(@Param("itemId") UUID itemId, @Param("userEmail") String userEmail);
}
