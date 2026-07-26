package ua.kse.passwordmanager.directory;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import ua.kse.passwordmanager.auth.AuthFacade;
import ua.kse.passwordmanager.common.ForbiddenException;
import ua.kse.passwordmanager.common.NotFoundException;
import ua.kse.passwordmanager.vault.PasswordItem;
import ua.kse.passwordmanager.vault.PasswordItemRepository;
import ua.kse.passwordmanager.audit.AuditAction;
import ua.kse.passwordmanager.audit.AuditService;
import ua.kse.passwordmanager.common.BadRequestException;
import org.springframework.transaction.annotation.Transactional;

/** Local governance APIs. They never mutate Google Workspace or Keycloak. */
@RestController
@RequestMapping("/api/admin/workspace")
public class WorkspaceAdminController {
    private final AuthFacade auth;
    private final WorkspaceDirectorySyncService sync;
    private final WorkspaceDirectoryClient directory;
    private final WorkspaceUserRepository users;
    private final WorkspaceGroupRepository groups;
    private final PasswordItemRepository items;
    private final AuditService audit;

    public WorkspaceAdminController(AuthFacade auth, WorkspaceDirectorySyncService sync,
            WorkspaceDirectoryClient directory, WorkspaceUserRepository users, WorkspaceGroupRepository groups,
            PasswordItemRepository items, AuditService audit) {
        this.auth = auth; this.sync = sync; this.directory = directory;
        this.users = users; this.groups = groups; this.items = items; this.audit = audit;
    }
    @PostMapping("/refresh")
    public WorkspaceDirectorySnapshotWriter.SyncResult refresh() { requireAdmin(); return sync.syncNow(); }

    /** Freshness of the Workspace snapshot and the credential behind it. Stale
     * or never-fetched data is the difference between "this account is not
     * allowed" and "Google could not be reached", so an administrator has to be
     * able to tell them apart — including whether the credential in use can
     * work unattended at all. */
    @GetMapping("/directory-status")
    public DirectoryStatusResponse directoryStatus() {
        requireAdmin();
        WorkspaceDirectorySyncService.DirectoryStatus status = sync.status();
        DirectoryCredentialSummary credential = directory.credentials();
        Instant snapshotSince = directory instanceof ResilientWorkspaceDirectoryClient resilient
                ? resilient.servingFromSnapshotSince() : null;
        return new DirectoryStatusResponse(status.lastSuccessAt(), status.lastAttemptAt(), status.lastError(),
                status.consecutiveFailures(), status.knownUsers(), credential.mode(), credential.unattended(),
                credential.detail(), credential.lastError(), snapshotSince);
    }

    public record DirectoryStatusResponse(Instant lastSuccessAt, Instant lastAttemptAt, String lastError,
                                          int consecutiveFailures, long knownUsers, String credentialMode,
                                          boolean credentialUnattended, String credentialDetail,
                                          String credentialError, Instant servingFromSnapshotSince) {}

    @GetMapping("/users")
    public List<UserResponse> users(@RequestParam(defaultValue = "") String query,
            @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "50") int size) {
        requireAdmin(); int safeSize = Math.clamp(size, 1, 200);
        return users.findByEmailContainingIgnoreCaseOrDisplayNameContainingIgnoreCase(query, query,
                PageRequest.of(Math.max(page, 0), safeSize)).map(UserResponse::from).toList();
    }
    @PatchMapping("/users/{email}")
    @Transactional
    public UserResponse updateUser(@PathVariable String email, @Valid @RequestBody UserChange change) {
        requireAdmin(); WorkspaceUser user = users.findById(email.toLowerCase())
                .orElseThrow(() -> new NotFoundException("Workspace user not found"));
        WorkspaceRoleOverride oldRole = user.effectiveRole();
        WorkspaceAccountStatus oldStatus = user.getStatus();
        if (change.status() == WorkspaceAccountStatus.REVOKED) {
            throw new BadRequestException("Use the recovery workflow to revoke a Workspace account");
        }
        WorkspaceRoleOverride override = change.roleOverride() != null ? change.roleOverride() : user.getRoleOverride();
        WorkspaceAccountStatus status = change.status() != null ? change.status() : user.getStatus();
        WorkspaceRoleOverride futureRole = override != null ? override
                : (user.isGoogleAdmin() ? WorkspaceRoleOverride.ADMIN : WorkspaceRoleOverride.USER);
        boolean remainsActiveAdmin = status == WorkspaceAccountStatus.ACTIVE && !user.isGoogleSuspended()
                && user.isDirectoryPresent() && futureRole == WorkspaceRoleOverride.ADMIN;
        if (oldRole == WorkspaceRoleOverride.ADMIN && user.hasEffectiveAccess() && !remainsActiveAdmin
                && activeAdminCount() <= 1) {
            throw new BadRequestException("Cannot remove the final active Workspace administrator");
        }
        if (change.roleOverride() != null) user.setRoleOverride(change.roleOverride());
        if (change.status() != null) user.setStatus(change.status());
        WorkspaceUser saved = users.save(user);
        if (oldRole != saved.effectiveRole()) audit.record(auth.current().email(), AuditAction.WORKSPACE_USER_ROLE_CHANGED,
                null, null, saved.getEmail(), oldRole + " -> " + saved.effectiveRole());
        if (oldStatus != saved.getStatus()) audit.record(auth.current().email(), AuditAction.WORKSPACE_USER_STATUS_CHANGED,
                null, null, saved.getEmail(), oldStatus + " -> " + saved.getStatus());
        return UserResponse.from(saved);
    }
    @GetMapping("/groups")
    public List<GroupResponse> groups() { requireAdmin(); return groups.findAll().stream().map(GroupResponse::from).toList(); }
    @PatchMapping("/groups/{email}")
    public GroupResponse updateGroup(@PathVariable String email, @Valid @RequestBody GroupChange change) {
        requireAdmin(); WorkspaceGroup group = groups.findById(email.toLowerCase())
                .orElseThrow(() -> new NotFoundException("Workspace group not found"));
        group.setVisibleToUsers(change.visibleToUsers()); return GroupResponse.from(groups.save(group));
    }
    @GetMapping("/records")
    public List<RecordMetadata> records() {
        requireAdmin(); return items.findAll().stream().map(RecordMetadata::from).toList();
    }
    private void requireAdmin() { if (!auth.current().isAdmin()) throw new ForbiddenException("Administrator role required"); }
    private long activeAdminCount() {
        return users.findAll().stream().filter(WorkspaceUser::hasEffectiveAccess)
                .filter(user -> user.effectiveRole() == WorkspaceRoleOverride.ADMIN).count();
    }

    public record UserChange(WorkspaceRoleOverride roleOverride, WorkspaceAccountStatus status) {}
    public record GroupChange(@NotNull Boolean visibleToUsers) {}
    public record UserResponse(String email, String directoryId, String displayName, boolean googleAdmin,
            WorkspaceRoleOverride roleOverride, WorkspaceRoleOverride effectiveRole, WorkspaceAccountStatus status,
            boolean googleSuspended, boolean directoryPresent, java.time.Instant syncedAt) {
        static UserResponse from(WorkspaceUser u) { return new UserResponse(u.getEmail(), u.getDirectoryId(), u.getDisplayName(), u.isGoogleAdmin(), u.getRoleOverride(), u.effectiveRole(), u.getStatus(), u.isGoogleSuspended(), u.isDirectoryPresent(), u.getSyncedAt()); }
    }
    public record GroupResponse(String email, String directoryId, String displayName, boolean visibleToUsers, java.time.Instant syncedAt) {
        static GroupResponse from(WorkspaceGroup g) { return new GroupResponse(g.getEmail(), g.getDirectoryId(), g.getDisplayName(), g.isVisibleToUsers(), g.getSyncedAt()); }
    }
    /** Intentionally excludes every ciphertext/key/IV and attachment byte. */
    public record RecordMetadata(UUID id, String name, String ownerEmail, String type, String itemType,
            String syncMode, java.time.Instant createdAt, java.time.Instant updatedAt) {
        static RecordMetadata from(PasswordItem item) { return new RecordMetadata(item.getId(), item.getName(), item.getOwnerEmail(), item.getType().name(), item.getItemType().name(), item.getSyncMode().name(), item.getCreatedAt(), item.getUpdatedAt()); }
    }
}
