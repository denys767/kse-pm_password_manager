package ua.kse.passwordmanager.vault;

import java.util.List;
import java.util.Collection;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface PasswordItemRepository extends JpaRepository<PasswordItem, UUID> {

    List<PasswordItem> findByOwnerEmailOrderByNameAsc(String ownerEmail);

    List<PasswordItem> findByOwnerEmail(String ownerEmail);

    List<PasswordItem> findByCollectionIdInOrderByNameAsc(Collection<UUID> collectionIds);

    long countByCollectionId(UUID collectionId);

    @Query("""
            select distinct p.item from Permission p
            where p.granteeType = ua.kse.passwordmanager.sharing.GranteeType.USER
              and p.status = ua.kse.passwordmanager.sharing.PermissionStatus.ACTIVE
              and lower(p.grantee) = lower(:email)
            """)
    List<PasswordItem> findSharedWith(@Param("email") String email);

    @Query("""
            select distinct p.item from PermissionMember m join m.permission p
            where lower(m.memberEmail) = lower(:email)
              and m.status = ua.kse.passwordmanager.sharing.PermissionMemberStatus.ACTIVE
              and p.status = ua.kse.passwordmanager.sharing.PermissionStatus.ACTIVE
            """)
    List<PasswordItem> findDirectorySharedWith(@Param("email") String email);
}
