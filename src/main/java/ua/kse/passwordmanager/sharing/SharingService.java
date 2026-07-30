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
import ua.kse.passwordmanager.passkeys.PasskeyCredentialKeyRepository;
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
    private final ua.kse.passwordmanager.collections.CollectionRepository collectionRepository;
    private final PermissionMemberRepository permissionMemberRepository;
    private final PasskeyCredentialKeyRepository passkeyKeyRepository;
    private final WorkspaceDirectoryClient directory;
    private final WorkspaceGroupRepository workspaceGroups;
    private final AuditService auditService;
    private final boolean development;

    public SharingService(PermissionRepository permissionRepository,
                          PasswordItemRepository itemRepository,
                          ItemKeyRepository itemKeyRepository,
                          CollectionMemberRepository collectionMemberRepository,
                          ua.kse.passwordmanager.collections.CollectionRepository collectionRepository,
                          PermissionMemberRepository permissionMemberRepository,
                          PasskeyCredentialKeyRepository passkeyKeyRepository,
                          WorkspaceDirectoryClient directory,
                          WorkspaceGroupRepository workspaceGroups,
                          AuditService auditService, Environment environment) {
        this.permissionRepository = permissionRepository;
        this.itemRepository = itemRepository;
        this.itemKeyRepository = itemKeyRepository;
        this.collectionMemberRepository = collectionMemberRepository;
        this.collectionRepository = collectionRepository;
        this.permissionMemberRepository = permissionMemberRepository;
        this.passkeyKeyRepository = passkeyKeyRepository;
        this.directory = directory;
        this.workspaceGroups = workspaceGroups;
        this.auditService = auditService;
        this.development = java.util.List.of(environment.getActiveProfiles()).contains("dev");
    }

    /**
     * Everyone other than the owner whose effective role on this item may use
     * its passkeys — the exact set that needs a wrapped credential key, and the
     * mirror image of the {@code mayUsePasskeys()} check
     * {@code PasskeyService.canUse()} applies on the way back out. Group
     * members and collection members count, because they can reach the
     * credential just as a direct grantee can.
     */
    @Transactional(readOnly = true)
    public java.util.Set<String> passkeyCapableGrantees(PasswordItem item) {
        java.util.Set<String> emails = new java.util.LinkedHashSet<>();
        for (Permission permission : permissionRepository.findByItemId(item.getId())) {
            if (!permission.isActive() || !permission.getRole().accessRole().mayUsePasskeys()) continue;
            switch (permission.getGranteeType()) {
                case USER -> emails.add(permission.getGrantee().toLowerCase(Locale.ROOT));
                case GROUP -> permissionMemberRepository.findByPermissionId(permission.getId()).stream()
                        .filter(member -> member.getStatus() == PermissionMemberStatus.ACTIVE)
                        .forEach(member -> emails.add(member.getMemberEmail().toLowerCase(Locale.ROOT)));
            }
        }
        if (item.getCollectionId() != null) {
            collectionMemberRepository.findByCollectionId(item.getCollectionId()).stream()
                    .filter(member -> member.getStatus().hasCryptographicAccess())
                    .forEach(member -> emails.add(member.getMemberEmail().toLowerCase(Locale.ROOT)));
        }
        emails.remove(item.getOwnerEmail().toLowerCase(Locale.ROOT));
        return emails;
    }

    /** Who one grant actually covers: the grantee for a user grant, the active
     * members for a group grant. */
    private java.util.Set<String> granteesOf(Permission permission) {
        if (permission.getGranteeType() == GranteeType.USER) {
            return java.util.Set.of(permission.getGrantee().toLowerCase(Locale.ROOT));
        }
        return permissionMemberRepository.findByPermissionId(permission.getId()).stream()
                .map(member -> member.getMemberEmail().toLowerCase(Locale.ROOT))
                .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
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
        ShareableAccess access = shareableAccess(user, itemId);
        PasswordItem item = access.item();
        requireGrantableBy(access.role(), request.role());
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
        if (request.granteeType() == GranteeType.USER) {
            requireRestrictionIsEnforceable(item, resolvedGrantee, request.role());
        } else {
            for (String email : directory.memberEmails(request.directorySubjectId())) {
                requireRestrictionIsEnforceable(item, email.toLowerCase(Locale.ROOT), request.role());
            }
        }
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
                request.granteeType() == GranteeType.GROUP ? GROUP_SHARE_WARNING : null,
                request.granteeType() == GranteeType.GROUP ? groupVisibleToUsers(resolvedGrantee) : null);
    }

    public List<PermissionResponse> listPermissions(CurrentUser user, UUID itemId) {
        shareableItem(user, itemId);
        return permissionRepository.findByItemId(itemId).stream()
                .map(permission -> PermissionResponse.from(permission, null,
                        permission.getGranteeType() == GranteeType.GROUP ? groupVisibleToUsers(permission.getGrantee()) : null))
                .toList();
    }

    private boolean groupVisibleToUsers(String groupEmail) {
        return workspaceGroups.findById(groupEmail).map(WorkspaceGroup::isVisibleToUsers).orElse(false);
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

    /**
     * Changes the role of an existing grant in place. Re-posting the share
     * would do this too, but for a group it also re-reads the directory and
     * resets every member to PENDING_PROVISIONING — losing access the owner
     * never meant to touch. Key material follows the new role: a role without
     * password access loses its wrapped key, and regaining one requires a
     * freshly wrapped key (users) or a re-provision (groups).
     */
    @Transactional
    public PermissionResponse updateRole(CurrentUser user, UUID itemId, UUID permissionId,
                                         UpdatePermissionRoleRequest request) {
        PasswordItem item = ownedItem(user, itemId);
        Permission permission = permissionRepository.findByIdAndItemId(permissionId, itemId)
                .orElseThrow(() -> new NotFoundException("Permission not found"));
        PermissionRole previous = permission.getRole();
        PermissionRole role = request.role();
        // Downgrading to a restricted role on a collection item promises the
        // same unenforceable restriction that share() refuses.
        for (String grantee : granteesOf(permission)) {
            requireRestrictionIsEnforceable(item, grantee, role);
        }
        boolean wrappedKeyProvided = request.wrappedKey() != null && !request.wrappedKey().isBlank();
        // Passkey material follows the role the same way the item key does: a
        // role that may not use passkeys keeps no wrapped credential key.
        if (!role.accessRole().mayUsePasskeys()) {
            for (String grantee : granteesOf(permission)) {
                passkeyKeyRepository.deleteByItemIdAndUserEmail(itemId, grantee);
            }
        }
        if (permission.getGranteeType() == GranteeType.USER) {
            String grantee = permission.getGrantee();
            if (!role.requiresItemKey()) {
                itemKeyRepository.deleteByItemIdAndUserEmail(itemId, grantee);
            } else if (wrappedKeyProvided) {
                itemKeyRepository.findByItemIdAndUserEmail(itemId, grantee)
                        .ifPresentOrElse(existing -> { existing.setWrappedKey(request.wrappedKey()); itemKeyRepository.save(existing); },
                                () -> itemKeyRepository.save(new ItemKey(item, grantee, request.wrappedKey())));
            } else if (itemKeyRepository.findByItemIdAndUserEmail(itemId, grantee).isEmpty()) {
                throw new BadRequestException(
                        "wrappedKey is required: wrap the item key with the recipient's public key");
            }
        } else if (!role.requiresItemKey()) {
            for (PermissionMember member : permissionMemberRepository.findByPermissionId(permissionId)) {
                itemKeyRepository.deleteByItemIdAndUserEmail(itemId, member.getMemberEmail());
            }
        } else if (!previous.requiresItemKey()) {
            // The downgrade above dropped the members' keys, so the group needs
            // a new Provision pass before anyone can decrypt again.
            for (PermissionMember member : permissionMemberRepository.findByPermissionId(permissionId)) {
                if (member.getStatus() == PermissionMemberStatus.ACTIVE) {
                    member.setStatus(PermissionMemberStatus.PENDING_PROVISIONING);
                    permissionMemberRepository.save(member);
                }
            }
        }
        permission.setRole(role);
        permission = permissionRepository.save(permission);
        auditService.record(user.email(), AuditAction.PERMISSION_ROLE_CHANGED, item.getId(), item.getName(),
                permission.getGrantee(), permission.getGranteeType() + " role " + previous + " -> " + role);
        boolean group = permission.getGranteeType() == GranteeType.GROUP;
        return PermissionResponse.from(permission,
                group && !previous.requiresItemKey() && role.requiresItemKey() ? GROUP_SHARE_WARNING : null,
                group ? groupVisibleToUsers(permission.getGrantee()) : null);
    }

    @Transactional
    public void revoke(CurrentUser user, UUID itemId, UUID permissionId) {
        PasswordItem item = ownedItem(user, itemId);
        Permission permission = permissionRepository.findByIdAndItemId(permissionId, itemId)
                .orElseThrow(() -> new NotFoundException("Permission not found"));
        // Delete children before touching item_keys; the latter can trigger an
        // automatic flush and would otherwise violate the FK on H2/Postgres.
        java.util.Set<String> revoked = granteesOf(permission);
        permissionMemberRepository.deleteByPermissionId(permissionId);
        permissionRepository.delete(permission);
        if (permission.getGranteeType() == GranteeType.USER) {
            itemKeyRepository.deleteByItemIdAndUserEmail(itemId, permission.getGrantee());
        }
        for (String grantee : revoked) {
            passkeyKeyRepository.deleteByItemIdAndUserEmail(itemId, grantee);
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
        return shareableAccess(user, itemId).item();
    }

    private record ShareableAccess(PasswordItem item, AccessRole role) { }

    private ShareableAccess shareableAccess(CurrentUser user, UUID itemId) {
        PasswordItem item = itemRepository.findById(itemId)
                .orElseThrow(() -> new NotFoundException("Item not found"));
        AccessRole role = resolveAccess(item, user);
        if (!role.canCreateShares()) {
            throw new ForbiddenException("Only the owner or an editor can add shares");
        }
        return new ShareableAccess(item, role);
    }

    /**
     * An editor may widen access, but not to another editor. Only the owner can
     * revoke or change a grant ({@link #ownedItem}), so an editor granting
     * EDITOR built a chain of re-sharers the owner could not unwind — and each
     * link could add another. Capping editors below their own level breaks the
     * chain, because the roles they can still grant cannot share at all.
     */
    private static void requireGrantableBy(AccessRole sharer, PermissionRole granted) {
        if (sharer.isOwner()) return;
        if (granted == PermissionRole.EDITOR) {
            throw new ForbiddenException("Only the owner can grant editor access");
        }
    }

    /**
     * Items in a collection carry their item key wrapped with the *collection*
     * key, so every provisioned member can already decrypt them. Accepting a
     * PASSKEY_ONLY or AUTOFILL_ONLY grant for such a member would promise a
     * restriction that no server check can keep — resolveAccess merges them up
     * to VIEWER precisely because that is what the cryptography already allows.
     * Refusing the grant is the honest answer; the owner has to take the item
     * out of the collection to restrict anyone in it.
     */
    private void requireRestrictionIsEnforceable(PasswordItem item, String grantee, PermissionRole role) {
        if (role.accessRole().canReadItemCiphertext() || item.getCollectionId() == null) return;
        boolean provisionedMember = collectionMemberRepository
                .findByCollectionIdAndMemberEmail(item.getCollectionId(), grantee)
                .filter(member -> member.getStatus().hasCryptographicAccess())
                .isPresent();
        if (!provisionedMember) return;
        String collectionName = collectionRepository.findById(item.getCollectionId())
                .map(ua.kse.passwordmanager.collections.Collection::getName)
                .orElse(item.getCollectionId().toString());
        throw new BadRequestException(grantee + " already has full access through collection \""
                + collectionName + "\"; remove the item from the collection before restricting them");
    }

    private void upsertMember(Permission permission, String email, PermissionMemberStatus status) {
        PermissionMember member = permissionMemberRepository.findByPermissionId(permission.getId()).stream()
                .filter(existing -> existing.getMemberEmail().equalsIgnoreCase(email)).findFirst()
                .orElseGet(() -> new PermissionMember(permission, email, status));
        member.setStatus(status);
        permissionMemberRepository.save(member);
    }
}
