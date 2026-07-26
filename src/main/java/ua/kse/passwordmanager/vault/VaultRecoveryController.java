package ua.kse.passwordmanager.vault;

import jakarta.validation.Valid;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ua.kse.passwordmanager.audit.AuditAction;
import ua.kse.passwordmanager.audit.AuditService;
import ua.kse.passwordmanager.auth.AuthFacade;
import ua.kse.passwordmanager.auth.CurrentUser;
import ua.kse.passwordmanager.collections.Collection;
import ua.kse.passwordmanager.collections.CollectionMember;
import ua.kse.passwordmanager.collections.CollectionMemberRepository;
import ua.kse.passwordmanager.collections.CollectionRepository;
import ua.kse.passwordmanager.collections.CollectionRole;
import ua.kse.passwordmanager.common.BadRequestException;
import ua.kse.passwordmanager.common.ForbiddenException;
import ua.kse.passwordmanager.directory.WorkspaceUser;
import ua.kse.passwordmanager.directory.WorkspaceUserRepository;
import ua.kse.passwordmanager.keys.UserKeys;
import ua.kse.passwordmanager.keys.UserKeysDto;
import ua.kse.passwordmanager.keys.UserKeysRepository;
import ua.kse.passwordmanager.sharing.GranteeType;
import ua.kse.passwordmanager.sharing.Permission;
import ua.kse.passwordmanager.sharing.PermissionMemberRepository;
import ua.kse.passwordmanager.sharing.PermissionRepository;

/** Recovery deliberately never accepts a vault passphrase: it only destroys or
 * transfers encrypted material after a fresh SSO authentication. */
@RestController
@RequestMapping("/api/vault")
public class VaultRecoveryController {
    private final AuthFacade auth;
    private final PasswordItemRepository items;
    private final ItemKeyRepository itemKeys;
    private final ItemVersionRepository versions;
    private final PermissionRepository permissions;
    private final PermissionMemberRepository permissionMembers;
    private final CollectionRepository collections;
    private final CollectionMemberRepository members;
    private final UserKeysRepository userKeys;
    private final WorkspaceUserRepository workspaceUsers;
    private final AuditService audit;

    public VaultRecoveryController(AuthFacade auth, PasswordItemRepository items,
            ItemKeyRepository itemKeys, ItemVersionRepository versions, PermissionRepository permissions,
            PermissionMemberRepository permissionMembers, CollectionRepository collections, CollectionMemberRepository members,
            UserKeysRepository userKeys, WorkspaceUserRepository workspaceUsers, AuditService audit) {
        this.auth = auth; this.items = items; this.itemKeys = itemKeys; this.versions = versions;
        this.permissions = permissions; this.permissionMembers = permissionMembers;
        this.collections = collections; this.members = members;
        this.userKeys = userKeys; this.workspaceUsers = workspaceUsers; this.audit = audit;
    }

    @GetMapping("/reset-impact")
    public ResetImpact impact() {
        CurrentUser user = auth.current();
        return impactFor(user.email());
    }

    /** Returns the refreshed impact so the caller sees the remaining blockers:
     * the reset screen has no other way to know a transfer succeeded, and an
     * empty 200 body used to surface as a JSON parse error in the browser. */
    @PostMapping("/ownership-transfers")
    @Transactional
    public ResetImpact transfer(@Valid @RequestBody OwnershipTransfer request) {
        requireRecentAuth();
        CurrentUser user = auth.current();
        String successor = request.successorEmail().trim().toLowerCase();
        if (successor.equals(user.email())) throw new BadRequestException("Choose another owner");
        if (request.kind() == TransferKind.ITEM) {
            PasswordItem item = items.findById(request.resourceId()).orElseThrow(() -> new BadRequestException("Item not found"));
            if (!user.email().equals(item.getOwnerEmail())) throw new ForbiddenException("Only the owner can transfer an item");
            // The outgoing owner has lost their passphrase, so nobody can wrap
            // the item key for a newcomer: only someone who already holds a
            // wrapped copy can become the owner.
            boolean canDecrypt = itemKeys.findByItemIdAndUserEmail(item.getId(), successor).isPresent();
            if (!canDecrypt) throw new BadRequestException("Successor must already have encrypted access to this item");
            item.setOwnerEmail(successor);
            // Ownership supersedes any grant the successor held; leaving the row
            // would make them appear in their own item's access list.
            permissions.findByItemIdAndGranteeTypeAndGrantee(item.getId(), GranteeType.USER, successor)
                    .ifPresent(this::deletePermission);
            audit.record(user.email(), AuditAction.OWNERSHIP_TRANSFERRED, item.getId(), item.getName(), successor, "item ownership transferred for vault recovery");
        } else {
            Collection collection = collections.findById(request.resourceId()).orElseThrow(() -> new BadRequestException("Collection not found"));
            if (!user.email().equals(collection.getOwnerEmail())) throw new ForbiddenException("Only the owner can transfer a collection");
            CollectionMember member = members.findByCollectionIdAndMemberEmail(collection.getId(), successor)
                    .orElseThrow(() -> new BadRequestException("Successor must be a collection member"));
            if (!member.getStatus().hasCryptographicAccess()) {
                throw new BadRequestException("Successor has no provisioned collection key yet");
            }
            collection.setOwnerEmail(successor);
            // Without this the new owner keeps whatever role they had (typically
            // VIEWER) and cannot manage the collection they now own.
            member.setRole(CollectionRole.MANAGER);
            members.save(member);
            for (PasswordItem item : items.findByCollectionIdInOrderByNameAsc(List.of(collection.getId()))) {
                if (user.email().equals(item.getOwnerEmail())) item.setOwnerEmail(successor);
            }
            audit.record(user.email(), AuditAction.OWNERSHIP_TRANSFERRED, collection.getId(), collection.getName(), successor, "collection ownership transferred for vault recovery");
        }
        return impactFor(user.email());
    }

    @PostMapping("/reset")
    @Transactional
    public UserKeysDto reset(@Valid @RequestBody ResetRequest request) {
        requireRecentAuth();
        CurrentUser user = auth.current();
        if (!"RESET VAULT".equals(request.confirmation())) throw new BadRequestException("Type RESET VAULT to confirm");
        ResetImpact impact = impactFor(user.email());
        if (!impact.blockers().isEmpty()) throw new BadRequestException("Transfer ownership before resetting the vault");

        for (PasswordItem item : items.findByOwnerEmail(user.email())) deleteItem(item);
        for (Collection collection : collections.findByOwnerEmail(user.email())) {
            boolean hasOtherMembers = members.findByCollectionId(collection.getId()).stream()
                    .anyMatch(member -> !user.email().equals(member.getMemberEmail()));
            if (!hasOtherMembers) {
                members.deleteByCollectionId(collection.getId());
                collections.delete(collection);
            }
        }
        for (Permission permission : permissions.findByGranteeTypeAndGrantee(GranteeType.USER, user.email())) {
            itemKeys.deleteByItemIdAndUserEmail(permission.getItem().getId(), user.email());
            deletePermission(permission);
        }
        // Group grants materialize one row per member; a leftover row would keep
        // the account listed on records it can no longer decrypt.
        permissionMembers.deleteByMemberEmail(user.email());
        for (CollectionMember member : members.findByMemberEmail(user.email())) {
            members.delete(member);
        }
        itemKeys.deleteByUserEmail(user.email());

        UserKeys replacement = userKeys.findById(user.email()).orElseGet(() -> new UserKeys(user.email()));
        replacement.setPublicKey(request.keys().publicKey());
        replacement.setEncryptedPrivateKey(request.keys().encryptedPrivateKey());
        replacement.setPrivateKeyIv(request.keys().privateKeyIv());
        replacement.setKdfSalt(request.keys().kdfSalt());
        replacement.setKdfAlgorithm(request.keys().kdfAlgorithm());
        userKeys.save(replacement);
        audit.record(user.email(), AuditAction.VAULT_RESET, null, null, null, "vault keypair reset after recovery");
        return UserKeysDto.from(replacement);
    }

    private ResetImpact impactFor(String email) {
        List<ResetBlocker> blockers = new ArrayList<>();
        List<StrandedResource> stranded = new ArrayList<>();
        for (PasswordItem item : items.findByOwnerEmail(email)) {
            if (permissions.findByItemId(item.getId()).isEmpty()) continue;
            List<Successor> candidates = itemKeys.findByItemId(item.getId()).stream()
                    .map(ItemKey::getUserEmail)
                    .filter(candidate -> !candidate.equalsIgnoreCase(email))
                    .distinct().sorted().map(this::successor).toList();
            // Nobody else holds a wrapped copy of this item key, so no transfer
            // can preserve it. Blocking here would deadlock the reset: the
            // owner cannot wrap the key for anyone without the passphrase they
            // just lost. The item is deleted with the rest instead.
            if (candidates.isEmpty()) {
                stranded.add(new StrandedResource(TransferKind.ITEM, item.getId(), item.getName()));
                continue;
            }
            blockers.add(new ResetBlocker(TransferKind.ITEM, item.getId(), item.getName(), "shared record", candidates));
        }
        for (Collection collection : collections.findByOwnerEmail(email)) {
            List<CollectionMember> others = members.findByCollectionId(collection.getId()).stream()
                    .filter(member -> !email.equalsIgnoreCase(member.getMemberEmail())).toList();
            if (others.isEmpty()) continue;
            List<Successor> candidates = others.stream()
                    .filter(member -> member.getStatus().hasCryptographicAccess())
                    .map(CollectionMember::getMemberEmail).sorted().map(this::successor).toList();
            if (candidates.isEmpty()) {
                stranded.add(new StrandedResource(TransferKind.COLLECTION, collection.getId(), collection.getName()));
                continue;
            }
            blockers.add(new ResetBlocker(TransferKind.COLLECTION, collection.getId(), collection.getName(), "team collection", candidates));
        }
        long incoming = permissions.findByGranteeTypeAndGrantee(GranteeType.USER, email).size();
        return new ResetImpact(blockers.isEmpty(), items.findByOwnerEmail(email).size(), incoming,
                members.findByMemberEmail(email).size(), blockers, stranded);
    }

    /** Directory display name when the successor is a known Workspace user;
     * the raw address otherwise, so the picker is never empty-looking. */
    private Successor successor(String email) {
        return new Successor(email, workspaceUsers.findById(email).map(WorkspaceUser::getDisplayName).orElse(email));
    }

    private void deleteItem(PasswordItem item) {
        for (Permission permission : permissions.findByItemId(item.getId())) deletePermission(permission);
        itemKeys.deleteByItemId(item.getId());
        versions.deleteByItemId(item.getId());
        items.delete(item);
    }

    /** Group grants own permission_members rows; deleting the parent first
     * violates their foreign key when the delete is flushed. */
    private void deletePermission(Permission permission) {
        permissionMembers.deleteByPermissionId(permission.getId());
        permissions.delete(permission);
    }

    private void requireRecentAuth() {
        if (!auth.hasRecentAuthentication()) throw new ForbiddenException("Re-authenticate with SSO before resetting a vault");
    }

    public enum TransferKind { ITEM, COLLECTION }
    public record Successor(String email, String displayName) {}
    public record ResetBlocker(TransferKind kind, UUID id, String name, String reason, List<Successor> candidates) {}
    /** Shared resource with no possible successor: an item here is deleted by
     * the reset, a collection survives for its members but loses its owner. */
    public record StrandedResource(TransferKind kind, UUID id, String name) {}
    public record ResetImpact(boolean allowed, long ownedItemsToDelete, long incomingSharesToRemove,
                              long membershipsToRemove, List<ResetBlocker> blockers,
                              List<StrandedResource> stranded) {}
    public record OwnershipTransfer(TransferKind kind, UUID resourceId, String successorEmail) {}
    public record ResetRequest(String confirmation, @Valid UserKeysDto keys) {}
}
