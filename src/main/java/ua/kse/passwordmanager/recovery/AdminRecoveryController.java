package ua.kse.passwordmanager.recovery;

import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.web.bind.annotation.*;
import ua.kse.passwordmanager.auth.AuthFacade;
import ua.kse.passwordmanager.common.ForbiddenException;

/** Recovery is deliberately separate from ordinary Workspace user PATCH APIs.
 * It requires a current local admin and a recent interactive SSO assertion. */
@RestController
@RequestMapping("/api/admin/recovery")
public class AdminRecoveryController {
    private final RecoveryService recovery; private final AuthFacade auth; private final RecoveryOperationRepository operations;
    public AdminRecoveryController(RecoveryService recovery, AuthFacade auth, RecoveryOperationRepository operations) { this.recovery = recovery; this.auth = auth; this.operations = operations; }
    @GetMapping("/coverage") public RecoveryDtos.CoverageResponse coverage() { requireAdmin(); return recovery.workspaceCoverage(); }
    @PostMapping("/operations") public RecoveryDtos.OperationResponse operation(@Valid @RequestBody AdminOperationRequest request) {
        requireAdminAndRecent();
        if (request.operationType() != RecoveryOperationType.REVOKE_TRANSFER) throw new IllegalArgumentException("Unsupported recovery operation type");
        return RecoveryDtos.OperationResponse.from(recovery.revokeAndTransfer(auth.current().email(), request.subjectEmail(), new RecoveryDtos.RevokeRequest(request.successorEmail(), request.reason())));
    }
    @GetMapping("/operations/{id}") public RecoveryDtos.OperationResponse operation(@PathVariable UUID id) { requireAdmin(); return RecoveryDtos.OperationResponse.from(operations.findById(id).orElseThrow(() -> new ua.kse.passwordmanager.common.NotFoundException("Recovery operation not found"))); }
    @PostMapping("/operations/{id}/retry") public RecoveryDtos.OperationResponse retry(@PathVariable UUID id) { requireAdminAndRecent(); return RecoveryDtos.OperationResponse.from(recovery.retry(auth.current().email(), id)); }
    private void requireAdmin() { if (!auth.current().isAdmin()) throw new ForbiddenException("Administrator role required"); }
    private void requireAdminAndRecent() { requireAdmin(); if (!auth.hasRecentAuthentication()) throw new ForbiddenException("Re-authenticate with SSO before recovery"); }
    public record AdminOperationRequest(RecoveryOperationType operationType, String subjectEmail, String successorEmail, String reason) { }
}
