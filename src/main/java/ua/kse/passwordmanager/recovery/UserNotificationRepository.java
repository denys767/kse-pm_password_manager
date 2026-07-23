package ua.kse.passwordmanager.recovery;

import java.util.*;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserNotificationRepository extends JpaRepository<UserNotification, UUID> {
    List<UserNotification> findByRecipientEmailOrderByCreatedAtDesc(String email);
}
