package ua.kse.passwordmanager.sharing;

import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ua.kse.passwordmanager.audit.AuditAction;
import ua.kse.passwordmanager.audit.AuditService;
import ua.kse.passwordmanager.auth.CurrentUser;
import ua.kse.passwordmanager.common.BadRequestException;
import ua.kse.passwordmanager.common.ForbiddenException;
import ua.kse.passwordmanager.common.NotFoundException;
import ua.kse.passwordmanager.vault.ItemKey;
import ua.kse.passwordmanager.vault.ItemKeyRepository;
import ua.kse.passwordmanager.vault.ItemType;
import ua.kse.passwordmanager.vault.PasswordItem;
import ua.kse.passwordmanager.vault.PasswordItemRepository;

@Service
public class SharingService {

    /** Temporary until collections (org-key model) land in Phase 3. */
    static final String GROUP_SHARE_WARNING =
            "Group members without a provisioned wrapped key cannot decrypt this item yet";

    private final PermissionRepository permissionRepository;
    private final PasswordItemRepository itemRepository;
    private final ItemKeyRepository itemKeyRepository;
    private final AuditService auditService;

    public SharingService(PermissionRepository permissionRepository,
                          PasswordItemRepository itemRepository,
                          ItemKeyRepository itemKeyRepository,
                          AuditService auditService) {
        this.permissionRepository = permissionRepository;
        this.itemRepository = itemRepository;
        this.itemKeyRepository = itemKeyRepository;
        this.auditService = auditService;
    }

    /** Effective role of the user on an item: ownership wins, then the highest
     * of direct user permissions and group permissions. */
    public AccessRole resolveAccess(PasswordItem item, CurrentUser user) {
        if (item.getOwnerEmail().equalsIgnoreCase(user.email())) {
            return AccessRole.OWNER;
        }
        AccessRole best = AccessRole.NONE;
        for (Permission permission : permissionRepository.findByItemId(item.getId())) {
            boolean matches = switch (permission.getGranteeType()) {
                case USER -> permission.getGrantee().equalsIgnoreCase(user.email());
                case GROUP -> user.groups().contains(permission.getGrantee().toLowerCase(Locale.ROOT));
            };
            if (!matches) {
                continue;
            }
            AccessRole granted = permission.getRole() == PermissionRole.EDITOR
                    ? AccessRole.EDITOR
                    : AccessRole.VIEWER;
            if (granted.ordinal() > best.ordinal()) {
                best = granted;
            }
        }
        return best;
    }

    @Transactional
    public PermissionResponse share(CurrentUser user, UUID itemId, ShareRequest request) {
        PasswordItem item = ownedItem(user, itemId);
        String grantee = request.grantee().trim().toLowerCase(Locale.ROOT);
        if (request.granteeType() == GranteeType.USER && grantee.equalsIgnoreCase(item.getOwnerEmail())) {
            throw new BadRequestException("Cannot share an item with its owner");
        }
        if (request.granteeType() == GranteeType.USER
                && (request.wrappedKey() == null || request.wrappedKey().isBlank())) {
            throw new BadRequestException(
                    "wrappedKey is required: wrap the item key with the recipient's public key");
        }

        Permission permission = permissionRepository
                .findByItemIdAndGranteeTypeAndGrantee(itemId, request.granteeType(), grantee)
                .map(existing -> {
                    existing.setRole(request.role());
                    return existing;
                })
                .orElseGet(() -> new Permission(item, request.granteeType(), grantee,
                        request.role(), user.email()));
        permission = permissionRepository.save(permission);

        if (request.granteeType() == GranteeType.USER) {
            ItemKey itemKey = itemKeyRepository.findByItemIdAndUserEmail(itemId, grantee)
                    .map(existing -> {
                        existing.setWrappedKey(request.wrappedKey());
                        return existing;
                    })
                    .orElseGet(() -> new ItemKey(item, grantee, request.wrappedKey()));
            itemKeyRepository.save(itemKey);
        }

        // Once an item is shared with anyone, it is a shared item.
        if (item.getItemType() != ItemType.SHARED) {
            item.setItemType(ItemType.SHARED);
            itemRepository.save(item);
        }

        auditService.record(user.email(), AuditAction.ITEM_SHARED, item.getId(), item.getName(),
                grantee, request.granteeType() + " granted role " + request.role());
        return PermissionResponse.from(permission,
                request.granteeType() == GranteeType.GROUP ? GROUP_SHARE_WARNING : null);
    }

    public List<PermissionResponse> listPermissions(CurrentUser user, UUID itemId) {
        ownedItem(user, itemId);
        return permissionRepository.findByItemId(itemId).stream()
                .map(PermissionResponse::from)
                .toList();
    }

    @Transactional
    public void revoke(CurrentUser user, UUID itemId, UUID permissionId) {
        PasswordItem item = ownedItem(user, itemId);
        Permission permission = permissionRepository.findByIdAndItemId(permissionId, itemId)
                .orElseThrow(() -> new NotFoundException("Permission not found"));
        permissionRepository.delete(permission);
        if (permission.getGranteeType() == GranteeType.USER) {
            itemKeyRepository.deleteByItemIdAndUserEmail(itemId, permission.getGrantee());
        }
        auditService.record(user.email(), AuditAction.ACCESS_REVOKED, item.getId(), item.getName(),
                permission.getGrantee(), permission.getGranteeType() + " access revoked");
    }

    private PasswordItem ownedItem(CurrentUser user, UUID itemId) {
        PasswordItem item = itemRepository.findById(itemId)
                .orElseThrow(() -> new NotFoundException("Item not found"));
        AccessRole role = resolveAccess(item, user);
        if (!role.canRead()) {
            // Hide the item's existence from users without access.
            throw new NotFoundException("Item not found");
        }
        if (!role.isOwner()) {
            throw new ForbiddenException("Only the owner can manage access");
        }
        return item;
    }
}
