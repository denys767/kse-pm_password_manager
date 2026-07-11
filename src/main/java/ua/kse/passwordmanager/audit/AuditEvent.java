package ua.kse.passwordmanager.audit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "audit_events")
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Instant occurredAt;

    @Column(nullable = false)
    private String actorEmail;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditAction action;

    private UUID itemId;

    private String itemName;

    /** The user or group the action was directed at (share/revoke). */
    private String target;

    @Column(length = 1024)
    private String details;

    protected AuditEvent() {
    }

    public AuditEvent(String actorEmail, AuditAction action, UUID itemId, String itemName,
                      String target, String details) {
        this.occurredAt = Instant.now();
        this.actorEmail = actorEmail;
        this.action = action;
        this.itemId = itemId;
        this.itemName = itemName;
        this.target = target;
        this.details = details;
    }

    public Long getId() {
        return id;
    }

    public Instant getOccurredAt() {
        return occurredAt;
    }

    public String getActorEmail() {
        return actorEmail;
    }

    public AuditAction getAction() {
        return action;
    }

    public UUID getItemId() {
        return itemId;
    }

    public String getItemName() {
        return itemName;
    }

    public String getTarget() {
        return target;
    }

    public String getDetails() {
        return details;
    }
}
