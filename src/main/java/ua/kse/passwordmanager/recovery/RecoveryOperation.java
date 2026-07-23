package ua.kse.passwordmanager.recovery;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "recovery_operations")
public class RecoveryOperation {
    @Id private UUID id = UUID.randomUUID();
    @Enumerated(EnumType.STRING) @Column(nullable = false) private RecoveryOperationType operationType;
    @Enumerated(EnumType.STRING) @Column(nullable = false) private RecoveryOperationStatus status = RecoveryOperationStatus.PENDING;
    @Column(nullable = false) private String actorEmail;
    @Column(nullable = false) private String subjectEmail;
    private String successorEmail;
    @Column(nullable = false, length = 1024) private String reason;
    @Column(length = 2048) private String failureReason;
    @Column(nullable = false) private Instant createdAt;
    private Instant completedAt;
    protected RecoveryOperation() { }
    public RecoveryOperation(RecoveryOperationType type, String actor, String subject, String successor, String reason) {
        operationType = type; actorEmail = actor; subjectEmail = subject; successorEmail = successor; this.reason = reason;
    }
    @PrePersist void created() { createdAt = Instant.now(); }
    public UUID getId() { return id; } public RecoveryOperationType getOperationType() { return operationType; }
    public RecoveryOperationStatus getStatus() { return status; } public String getActorEmail() { return actorEmail; }
    public String getSubjectEmail() { return subjectEmail; } public String getSuccessorEmail() { return successorEmail; }
    public String getReason() { return reason; } public String getFailureReason() { return failureReason; }
    public Instant getCreatedAt() { return createdAt; } public Instant getCompletedAt() { return completedAt; }
    public void running() { status = RecoveryOperationStatus.RUNNING; }
    public void completed() { status = RecoveryOperationStatus.COMPLETED; completedAt = Instant.now(); failureReason = null; }
    public void failed(String reason) { status = RecoveryOperationStatus.FAILED; failureReason = reason; }
}
