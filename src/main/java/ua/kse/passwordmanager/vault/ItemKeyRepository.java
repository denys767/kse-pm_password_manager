package ua.kse.passwordmanager.vault;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ItemKeyRepository extends JpaRepository<ItemKey, UUID> {

    Optional<ItemKey> findByItemIdAndUserEmail(UUID itemId, String userEmail);

    List<ItemKey> findByUserEmail(String userEmail);

    void deleteByItemId(UUID itemId);

    void deleteByItemIdAndUserEmail(UUID itemId, String userEmail);

    void deleteByUserEmail(String userEmail);
}
