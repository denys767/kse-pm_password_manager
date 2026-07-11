package ua.kse.passwordmanager.sharing;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PermissionRepository extends JpaRepository<Permission, UUID> {

    List<Permission> findByItemId(UUID itemId);

    Optional<Permission> findByItemIdAndGranteeTypeAndGrantee(UUID itemId, GranteeType granteeType,
                                                              String grantee);

    Optional<Permission> findByIdAndItemId(UUID id, UUID itemId);

    void deleteByItemId(UUID itemId);
}
