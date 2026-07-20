package ua.kse.passwordmanager.collections;

import java.util.UUID;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CollectionRepository extends JpaRepository<Collection, UUID> {
    List<Collection> findByOwnerEmail(String ownerEmail);
}
