package ua.kse.passwordmanager.sharing;

import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.core.env.Environment;
import ua.kse.passwordmanager.audit.AuditAction;
import ua.kse.passwordmanager.audit.AuditService;
import ua.kse.passwordmanager.auth.CurrentUser;
import ua.kse.passwordmanager.collections.CollectionMemberRepository;
import ua.kse.passwordmanager.directory.DirectoryPrincipal;
import ua.kse.passwordmanager.directory.WorkspaceDirectoryClient;
import ua.kse.passwordmanager.directory.WorkspaceGroupRepository;
import ua.kse.passwordmanager.directory.WorkspaceGroup;
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
    private final CollectionMemberRepository collectionMemberRepository;
    private final PermissionMemberRepository permissionMemberRepository;
    private final WorkspaceDirectoryClient directory;
    private final WorkspaceGroupRepository workspaceGroups;
    private final AuditService auditService;
    private final boolean development;

    public SharingService(PermissionRepository permissionRepository,
                          PasswordItemRepository itemRepository,
                          ItemKeyRepository itemKeyRepository,
                          CollectionMemberRepository collectionMemberRepository,
                          PermissionMemberRepository permissionMemberRepository,
                          WorkspaceDirectoryClient directory,
                          WorkspaceGroupRepository workspaceGroups,
                          AuditService auditService, Environment environment) {
        this.permissionRepository = permissionRepository;
        this.itemRepository = itemRepository;
        this.itemKeyRepository = itemKeyRepository;
        this.collectionMemberRepository = collectionMemberRepository;
        this.permissionMemberRepository = permissionMemberRepository;
        this.directory = directory;
        this.workspaceGroups = workspaceGroups;
        this.auditService = auditService;
        this.development = java.util.List.of(environment.getActiveProfiles()).contains("dev");
    }

    /** Effective role of the user on an item: ownership wins, then the highest
     * of direct user permissions and group permissions. */
    public AccessRole resolveAccess(PasswordItem item, CurrentUser user) {
        if (item.getOwnerEmail().equalsIgnoreCase(user.email())) {
            return AccessRole.OWNER;
        }
        AccessRole best = AccessRole.NONE;
        for (Permission permission : permissionRepository.findByItemId(item.getId())) {
            boolean matches = permission.isActive() && switch (permission.getGranteeType()) {
                case USER -> permission.getGrantee().equalsIgnoreCase(user.email());
                case GROUP -> permissionMemberRepository
                        .existsByPermissionIdAndMemberEmailAndStatus(permission.getId(), user.email(), PermissionMemberStatus.ACTIVE);
            };
            if (!matches) {
                continue;
            }
            best = AccessRole.mostPermissive(best, permission.getRole().accessRole());
        }
        // Collection membership grants access to every item in the collection.
        if (item.getCollectionId() != null) {
            AccessRole viaCollection = collectionMemberRepository
                    .findByCollectionIdAndMemberEmail(item.getCollectionId(), user.email())
                    // A materialized Google group member has no usable access
                    // until a collection key was actually provisioned.  In
                    // particular PENDING_REMOVAL must block the API before a
                    // key rotation finishes.
                    .filter(member -> member.getStatus().hasCryptographicAccess())
                    .map(member -> member.getRole().canEditItems() ? AccessRole.EDITOR : AccessRole.VIEWER)
                    .orElse(AccessRole.NONE);
            best = AccessRole.mostPermissive(best, viaCollection);
        }
        return best;
    }

    @Transactional
    public PermissionResponse share(CurrentUser user, UUID itemId, ShareRequest request) {
        PasswordItem item = shareableItem(user, itemId);
        String grantee = request.grantee().trim().toLowerCase(Locale.ROOT);
        if (request.granteeType() == GranteeType.USER && grantee.equalsIgnoreCase(item.getOwnerEmail())) {
            throw new BadRequestException("Cannot share an item with its owner");
        }
        if (request.granteeType() == GranteeType.USER && request.role().requiresItemKey()
                && (request.wrappedKey() == null || request.wrappedKey().isBlank())) {
            throw new BadRequestException(
                    "wrappedKey is required: wrap the item key with the recipient's public key");
        }
        boolean directorySubjectMissing = request.directorySubjectId() == null || request.directorySubjectId().isBlank();
        // A GROUP share needs directory resolution to enumerate members (below),
        // so a legacy Keycloak group claim without a directorySubjectId must be
        // rejected here rather than fail later against the directory.
        if (request.granteeType() == GranteeType.GROUP && directorySubjectMissing) {
            throw new BadRequestException("directorySubjectId is required for a Google Workspace group");
        }
        // The Directory API accepts the primary email as a principal key, so a
        // USER share where the caller typed a full address instead of picking an
        // autocomplete suggestion is resolved here rather than rejected: the
        // invariant is "the grantee is a real, in-domain Workspace principal",
        // not "the client already knew its immutable id".
        DirectoryPrincipal principal = null;
        if (!directorySubjectMissing || !development) {
            String key = directorySubjectMissing ? grantee : request.directorySubjectId();
            principal = directory.find(request.granteeType() == GranteeType.USER
                            ? DirectoryPrincipal.Type.USER : DirectoryPrincipal.Type.GROUP, key)
                    .orElseThrow(() -> new BadRequestException("Directory principal was not found or is outside the domain"));
            grantee = principal.email().toLowerCase(Locale.ROOT);
            if (principal.type() == DirectoryPrincipal.Type.GROUP && !user.isAdmin()) {
                WorkspaceGroup group = workspaceGroups.findById(grantee)
                        .orElseThrow(() -> new BadRequestException("Google group is not materialized in Workspace"));
                if (!group.isDirectoryPresent() || !group.isVisibleToUsers()) {
                    throw new ForbiddenException("This Google Workspace group is not visible for sharing");
                }
            }
        }

        final String resolvedGrantee = grantee;
        Permission permission = permissionRepository
                .findByItemIdAndGranteeTypeAndGrantee(itemId, request.granteeType(), resolvedGrantee)
                .map(existing -> {
                    existing.setRole(request.role());
                    return existing;
                })
                .orElseGet(() -> new Permission(item, request.granteeType(), resolvedGrantee,
                        request.role(), user.email()));
        permission = permissionRepository.save(permission);
        if (principal != null) {
            permission.setDirectorySubject(principal.id(), principal.displayName());
            permission = permissionRepository.save(permission);
        }

        if (request.granteeType() == GranteeType.USER) {
            if (request.role().requiresItemKey()) {
                ItemKey itemKey = itemKeyRepository.findByItemIdAndUserEmail(itemId, resolvedGrantee)
                        .map(existing -> {
                            existing.setWrappedKey(request.wrappedKey());
                            return existing;
                        })
                        .orElseGet(() -> new ItemKey(item, resolvedGrantee, request.wrappedKey()));
                itemKeyRepository.save(itemKey);
            } else {
                // A downgrade to PASSKEY_ONLY must remove a previously granted
                // password key in the same transaction.
                itemKeyRepository.deleteByItemIdAndUserEmail(itemId, resolvedGrantee);
            }
            upsertMember(permission, resolvedGrantee, PermissionMemberStatus.ACTIVE);
        } else {
            for (String email : directory.memberEmails(permission.getDirectorySubjectId())) {
                upsertMember(permission, email, PermissionMemberStatus.PENDING_PROVISIONING);
            }
            if (request.memberWrappedKeys() != null) {
                for (ShareRequest.MemberWrappedKey entry : request.memberWrappedKeys()) {
                    String email = entry.email().trim().toLowerCase(Locale.ROOT);
                    boolean belongs = permissionMemberRepository.findByPermissionId(permission.getId()).stream()
                            .anyMatch(member -> member.getMemberEmail().equals(email));
                    if (!belongs) throw new BadRequestException("Wrapped key recipient is not a member of this group");
                    itemKeyRepository.findByItemIdAndUserEmail(itemId, email)
                            .ifPresentOrElse(existing -> { existing.setWrappedKey(entry.wrappedKey()); itemKeyRepository.save(existing); },
                                    () -> itemKeyRepository.save(new ItemKey(item, email, entry.wrappedKey())));
                    upsertMember(permission, email, PermissionMemberStatus.ACTIVE);
                }
            }
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
        shareableItem(user, itemId);
        return permissionRepository.findByItemId(itemId).stream()
                .map(PermissionResponse::from)
                .toList();
    }

    public List<PermissionMemberResponse> listMembers(CurrentUser user, UUID itemId, UUID permissionId) {
        shareableItem(user, itemId);
        permissionRepository.findByIdAndItemId(permissionId, itemId)
                .orElseThrow(() -> new NotFoundException("Permission not found"));
        return permissionMemberRepository.findByPermissionId(permissionId).stream().map(PermissionMemberResponse::from).toList();
    }

    @Transactional
    public void provisionMembers(CurrentUser user, UUID itemId, UUID permissionId, ProvisionPermissionMembersRequest request) {
        PasswordItem item = ownedItem(user, itemId);
        Permission permission = permissionRepository.findByIdAndItemId(permissionId, itemId)
                .orElseThrow(() -> new NotFoundException("Permission not found"));
        for (ProvisionPermissionMembersRequest.Entry entry : request.members()) {
            String email = entry.email().trim().toLowerCase(Locale.ROOT);
            PermissionMember member = permissionMemberRepository.findByPermissionId(permissionId).stream()
                    .filter(m -> m.getMemberEmail().equalsIgnoreCase(email)).findFirst()
                    .orElseThrow(() -> new BadRequestException("Recipient is not in this grant"));
            if (member.getStatus() == PermissionMemberStatus.PENDING_REMOVAL) {
                throw new BadRequestException("Recipient is pending removal");
            }
            itemKeyRepository.findByItemIdAndUserEmail(itemId, email)
                    .ifPresentOrElse(existing -> { existing.setWrappedKey(entry.wrappedKey()); itemKeyRepository.save(existing); },
                            () -> itemKeyRepository.save(new ItemKey(item, email, entry.wrappedKey())));
            member.setStatus(PermissionMemberStatus.ACTIVE);
            permissionMemberRepository.save(member);
        }
    }

    @Transactional
    public void syncGroup(CurrentUser user, UUID itemId, UUID permissionId) {
        ownedItem(user, itemId);
        Permission permission = permissionRepository.findByIdAndItemId(permissionId, itemId)
                .orElseThrow(() -> new NotFoundException("Permission not found"));
        if (permission.getGranteeType() != GranteeType.GROUP || !permission.isActive()) {
            throw new BadRequestException("Permission is not an active Google group grant");
        }
        var current = new java.util.HashSet<>(directory.memberEmails(permission.getDirectorySubjectId()));
        for (String email : current) {
            boolean known = permissionMemberRepository.findByPermissionId(permissionId).stream()
                    .anyMatch(member -> member.getMemberEmail().equalsIgnoreCase(email));
            if (!known) upsertMember(permission, email, PermissionMemberStatus.PENDING_PROVISIONING);
        }
        for (PermissionMember member : permissionMemberRepository.findByPermissionId(permissionId)) {
            if (!current.contains(member.getMemberEmail()) && member.getStatus() == PermissionMemberStatus.ACTIVE) {
                member.setStatus(PermissionMemberStatus.PENDING_REMOVAL);
                permissionMemberRepository.save(member);
            }
        }
    }

    @Transactional
    public void revoke(CurrentUser user, UUID itemId, UUID permissionId) {
        PasswordItem item = ownedItem(user, itemId);
        Permission permission = permissionRepository.findByIdAndItemId(permissionId, itemId)
                .orElseThrow(() -> new NotFoundException("Permission not found"));
        // Delete children before touching item_keys; the latter can trigger an
        // automatic flush and would otherwise violate the FK on H2/Postgres.
        permissionMemberRepository.deleteByPermissionId(permissionId);
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
        if (!role.canReadItemCiphertext()) {
            // Hide the item's existence from users without access.
            throw new NotFoundException("Item not found");
        }
        if (!role.canRevokeGrants()) {
            throw new ForbiddenException("Only the owner can manage access");
        }
        return item;
    }

    private PasswordItem shareableItem(CurrentUser user, UUID itemId) {
        PasswordItem item = itemRepository.findById(itemId)
                .orElseThrow(() -> new NotFoundException("Item not found"));
        if (!resolveAccess(item, user).canCreateShares()) {
            throw new ForbiddenException("Only the owner or an editor can add shares");
        }
        return item;
    }

    private void upsertMember(Permission permission, String email, PermissionMemberStatus status) {
        PermissionMember member = permissionMemberRepository.findByPermissionId(permission.getId()).stream()
                .filter(existing -> existing.getMemberEmail().equalsIgnoreCase(email)).findFirst()
                .orElseGet(() -> new PermissionMember(permission, email, status));
        member.setStatus(status);
        permissionMemberRepository.save(member);
    }
}
