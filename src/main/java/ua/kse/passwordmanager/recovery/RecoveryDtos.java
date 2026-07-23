package ua.kse.passwordmanager.recovery;

import jakarta.validation.constraints.*;
import java.time.Instant;
import java.util.UUID;

public final class RecoveryDtos {
    private RecoveryDtos() { }
    public record PublicKeyResponse(String keyVersion, String pem, String algorithm) { }
    public record EnvelopeRequest(@NotNull RecoveryResourceType resourceType, @NotNull UUID resourceId,
                                  @NotBlank @Size(max = 1024) String keyVersion,
                                  @NotBlank @Size(max = 8192) String ciphertext) { }
    public record CoverageResponse(long covered, long total, boolean enforcing) { }
    public record RevokeRequest(@NotBlank @Size(max = 255) String successorEmail,
                                @NotBlank @Size(max = 1024) String reason) { }
    public record OperationResponse(UUID id, RecoveryOperationType operationType, RecoveryOperationStatus status,
                                    String subjectEmail, String successorEmail, String failureReason,
                                    Instant createdAt, Instant completedAt) {
        static OperationResponse from(RecoveryOperation op) { return new OperationResponse(op.getId(), op.getOperationType(), op.getStatus(), op.getSubjectEmail(), op.getSuccessorEmail(), op.getFailureReason(), op.getCreatedAt(), op.getCompletedAt()); }
    }
}
