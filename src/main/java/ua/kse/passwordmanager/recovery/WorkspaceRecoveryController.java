package ua.kse.passwordmanager.recovery;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;
import ua.kse.passwordmanager.auth.AuthFacade;
import ua.kse.passwordmanager.common.ForbiddenException;

/** Stable convenience route for the user-administration screen. */
@RestController
@RequestMapping("/api/admin/workspace/users")
public class WorkspaceRecoveryController {
    private final RecoveryService recovery; private final AuthFacade auth;
    public WorkspaceRecoveryController(RecoveryService recovery, AuthFacade auth) { this.recovery = recovery; this.auth = auth; }
    @PostMapping("/{email}/revoke") public RecoveryDtos.OperationResponse revoke(@PathVariable String email, @Valid @RequestBody RecoveryDtos.RevokeRequest request) {
        if (!auth.current().isAdmin()) throw new ForbiddenException("Administrator role required");
        if (!auth.hasRecentAuthentication()) throw new ForbiddenException("Re-authenticate with SSO before recovery");
        return RecoveryDtos.OperationResponse.from(recovery.revokeAndTransfer(auth.current().email(), email, request));
    }
}
