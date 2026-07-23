package ua.kse.passwordmanager.attachment;

import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ItemAttachmentRepository extends JpaRepository<ItemAttachment, UUID> {
    Optional<ItemAttachment> findByItemId(UUID itemId);
}
