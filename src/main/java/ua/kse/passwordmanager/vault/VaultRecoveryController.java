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
import ua.kse.passwordmanager.common.BadRequestException;
import ua.kse.passwordmanager.common.ForbiddenException;
import ua.kse.passwordmanager.keys.UserKeys;
import ua.kse.passwordmanager.keys.UserKeysDto;
import ua.kse.passwordmanager.keys.UserKeysRepository;
import ua.kse.passwordmanager.sharing.GranteeType;
import ua.kse.passwordmanager.sharing.Permission;
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
    private final CollectionRepository collections;
    private final CollectionMemberRepository members;
    private final UserKeysRepository userKeys;
    private final AuditService audit;

    public VaultRecoveryController(AuthFacade auth, PasswordItemRepository items,
            ItemKeyRepository itemKeys, ItemVersionRepository versions, PermissionRepository permissions,
            CollectionRepository collections, CollectionMemberRepository members,
            UserKeysRepository userKeys, AuditService audit) {
        this.auth = auth; this.items = items; this.itemKeys = itemKeys; this.versions = versions;
        this.permissions = permissions; this.collections = collections; this.members = members;
        this.userKeys = userKeys; this.audit = audit;
    }

    @GetMapping("/reset-impact")
    public ResetImpact impact() {
        CurrentUser user = auth.current();
        return impactFor(user.email());
    }

    @PostMapping("/ownership-transfers")
    @Transactional
    public void transfer(@Valid @RequestBody OwnershipTransfer request) {
        requireRecentAuth();
        CurrentUser user = auth.current();
        String successor = request.successorEmail().trim().toLowerCase();
        if (successor.equals(user.email())) throw new BadRequestException("Choose another owner");
        if (request.kind() == TransferKind.ITEM) {
            PasswordItem item = items.findById(request.resourceId()).orElseThrow(() -> new BadRequestException("Item not found"));
            if (!user.email().equals(item.getOwnerEmail())) throw new ForbiddenException("Only the owner can transfer an item");
            boolean canDecrypt = itemKeys.findByItemIdAndUserEmail(item.getId(), successor).isPresent();
            if (!canDecrypt) throw new BadRequestException("Successor must already have encrypted access to this item");
            item.setOwnerEmail(successor);
            audit.record(user.email(), AuditAction.OWNERSHIP_TRANSFERRED, item.getId(), item.getName(), successor, "item ownership transferred for vault recovery");
        } else {
            Collection collection = collections.findById(request.resourceId()).orElseThrow(() -> new BadRequestException("Collection not found"));
            if (!user.email().equals(collection.getOwnerEmail())) throw new ForbiddenException("Only the owner can transfer a collection");
            boolean member = members.findByCollectionIdAndMemberEmail(collection.getId(), successor).isPresent();
            if (!member) throw new BadRequestException("Successor must be a collection member");
            collection.setOwnerEmail(successor);
            for (PasswordItem item : items.findByCollectionIdInOrderByNameAsc(List.of(collection.getId()))) {
                if (user.email().equals(item.getOwnerEmail())) item.setOwnerEmail(successor);
            }
            audit.record(user.email(), AuditAction.OWNERSHIP_TRANSFERRED, collection.getId(), collection.getName(), successor, "collection ownership transferred for vault recovery");
        }
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
            permissions.delete(permission);
        }
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
        for (PasswordItem item : items.findByOwnerEmail(email)) {
            if (!permissions.findByItemId(item.getId()).isEmpty()) {
                blockers.add(new ResetBlocker(TransferKind.ITEM, item.getId(), item.getName(), "shared record"));
            }
        }
        for (Collection collection : collections.findByOwnerEmail(email)) {
            if (members.findByCollectionId(collection.getId()).stream().anyMatch(m -> !email.equals(m.getMemberEmail()))) {
                blockers.add(new ResetBlocker(TransferKind.COLLECTION, collection.getId(), collection.getName(), "team collection"));
            }
        }
        long incoming = permissions.findByGranteeTypeAndGrantee(GranteeType.USER, email).size();
        return new ResetImpact(blockers.isEmpty(), items.findByOwnerEmail(email).size(), incoming,
                members.findByMemberEmail(email).size(), blockers);
    }

    private void deleteItem(PasswordItem item) {
        permissions.deleteByItemId(item.getId());
        itemKeys.deleteByItemId(item.getId());
        versions.deleteByItemId(item.getId());
        items.delete(item);
    }

    private void requireRecentAuth() {
        if (!auth.hasRecentAuthentication()) throw new ForbiddenException("Re-authenticate with SSO before resetting a vault");
    }

    public enum TransferKind { ITEM, COLLECTION }
    public record ResetBlocker(TransferKind kind, UUID id, String name, String reason) {}
    public record ResetImpact(boolean allowed, long ownedItemsToDelete, long incomingSharesToRemove,
                              long membershipsToRemove, List<ResetBlocker> blockers) {}
    public record OwnershipTransfer(TransferKind kind, UUID resourceId, String successorEmail) {}
    public record ResetRequest(String confirmation, @Valid UserKeysDto keys) {}
}
