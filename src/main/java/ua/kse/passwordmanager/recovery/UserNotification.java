package ua.kse.passwordmanager.recovery;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "user_notifications")
public class UserNotification {
    @Id private UUID id = UUID.randomUUID();
    @Column(nullable = false) private String recipientEmail;
    @Column(nullable = false) private String notificationType;
    @Column(nullable = false, length = 2048) private String message;
    private UUID recoveryOperationId;
    @Column(nullable = false) private Instant createdAt;
    private Instant readAt;
    protected UserNotification() { }
    public UserNotification(String recipient, String type, String message, UUID operationId) {
        recipientEmail = recipient; notificationType = type; this.message = message; recoveryOperationId = operationId;
    }
    @PrePersist void created() { createdAt = Instant.now(); }
    public UUID getId() { return id; } public String getRecipientEmail() { return recipientEmail; }
    public String getNotificationType() { return notificationType; } public String getMessage() { return message; }
    public UUID getRecoveryOperationId() { return recoveryOperationId; } public Instant getCreatedAt() { return createdAt; }
}
