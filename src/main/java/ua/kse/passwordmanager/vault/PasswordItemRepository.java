package ua.kse.passwordmanager.vault;

import java.util.Collection;
import java.util.List;
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
            where (p.granteeType = ua.kse.passwordmanager.sharing.GranteeType.USER
                   and lower(p.grantee) = lower(:email))
               or (p.granteeType = ua.kse.passwordmanager.sharing.GranteeType.GROUP
                   and lower(p.grantee) in :groups)
            """)
    List<PasswordItem> findSharedWith(@Param("email") String email,
                                      @Param("groups") Collection<String> groups);
}
