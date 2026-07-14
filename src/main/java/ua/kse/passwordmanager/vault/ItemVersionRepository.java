package ua.kse.passwordmanager.vault;

import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ItemVersionRepository extends JpaRepository<ItemVersion, UUID> {

    List<ItemVersion> findByItemIdOrderByReplacedAtDesc(UUID itemId);

    void deleteByItemId(UUID itemId);
}
