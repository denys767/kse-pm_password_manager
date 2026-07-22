package ua.kse.passwordmanager.vault;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ua.kse.passwordmanager.audit.AuditAction;
import ua.kse.passwordmanager.audit.AuditService;
import ua.kse.passwordmanager.auth.CurrentUser;
import ua.kse.passwordmanager.collections.CollectionMember;
import ua.kse.passwordmanager.collections.CollectionMemberRepository;
import ua.kse.passwordmanager.common.BadRequestException;
import ua.kse.passwordmanager.common.ForbiddenException;
import ua.kse.passwordmanager.common.NotFoundException;
import ua.kse.passwordmanager.sharing.AccessRole;
import ua.kse.passwordmanager.sharing.PermissionRepository;
import ua.kse.passwordmanager.sharing.SharingService;

@Service
public class VaultService {

    private final PasswordItemRepository itemRepository;
    private final PermissionRepository permissionRepository;
    private final ItemKeyRepository itemKeyRepository;
    private final ItemVersionRepository itemVersionRepository;
    private final CollectionMemberRepository collectionMemberRepository;
    private final SharingService sharingService;
    private final AuditService auditService;

    public VaultService(PasswordItemRepository itemRepository,
                        PermissionRepository permissionRepository,
                        ItemKeyRepository itemKeyRepository,
                        ItemVersionRepository itemVersionRepository,
                        CollectionMemberRepository collectionMemberRepository,
                        SharingService sharingService,
                        AuditService auditService) {
        this.itemRepository = itemRepository;
        this.permissionRepository = permissionRepository;
        this.itemKeyRepository = itemKeyRepository;
        this.itemVersionRepository = itemVersionRepository;
        this.collectionMemberRepository = collectionMemberRepository;
        this.sharingService = sharingService;
        this.auditService = auditService;
    }

    @Transactional(readOnly = true)
    public List<PasswordItemResponse> list(CurrentUser user) {
        Map<UUID, String> wrappedKeys = itemKeyRepository.findByUserEmail(user.email()).stream()
                .collect(Collectors.toMap(k -> k.getItem().getId(), ItemKey::getWrappedKey));
        List<PasswordItemResponse> result = new ArrayList<>();
        Set<UUID> seen = new HashSet<>();
        for (PasswordItem item : itemRepository.findByOwnerEmailOrderByNameAsc(user.email())) {
            seen.add(item.getId());
            result.add(PasswordItemResponse.from(item, AccessRole.OWNER, wrappedKeys.get(item.getId())));
        }
        for (PasswordItem item : itemRepository.findSharedWith(user.email())) {
            if (seen.add(item.getId())) {
                result.add(PasswordItemResponse.from(item, sharingService.resolveAccess(item, user),
                        wrappedKeys.get(item.getId())));
            }
        }
        for (PasswordItem item : itemRepository.findDirectorySharedWith(user.email())) {
            if (seen.add(item.getId())) {
                result.add(PasswordItemResponse.from(item, sharingService.resolveAccess(item, user),
                        wrappedKeys.get(item.getId())));
            }
        }
        // Items visible through collection membership.
        List<UUID> collectionIds = collectionMemberRepository.findByMemberEmail(user.email()).stream()
                .map(member -> member.getCollection().getId())
                .toList();
        if (!collectionIds.isEmpty()) {
            for (PasswordItem item : itemRepository.findByCollectionIdInOrderByNameAsc(collectionIds)) {
                if (seen.add(item.getId())) {
                    result.add(PasswordItemResponse.from(item,
                            sharingService.resolveAccess(item, user), wrappedKeys.get(item.getId())));
                }
            }
        }
        return result;
    }

    /**
     * Assign the item to a collection (wrappedKey = item key wrapped with the
     * collection key, produced client-side) or remove it with a null id.
     */
    @Transactional
    public PasswordItemResponse changeCollection(CurrentUser user, UUID id,
                                                 ItemCollectionRequest request) {
        var access = readableItem(user, id);
        if (!access.role().isOwner()) {
            throw new ForbiddenException("Only the owner can move an item between collections");
        }
        PasswordItem item = access.item();
        if (request.collectionId() == null) {
            item.setCollectionId(null);
            item.setCollectionWrappedKey(null);
            item.setCollectionWrappedKeyIv(null);
        } else {
            CollectionMember membership = collectionMemberRepository
                    .findByCollectionIdAndMemberEmail(request.collectionId(), user.email())
                    .orElseThrow(() -> new NotFoundException("Collection not found"));
            if (!membership.getRole().canEditItems()) {
                throw new ForbiddenException("A viewer cannot add items to the collection");
            }
            if (request.wrappedKey() == null || request.wrappedKey().isBlank()
                    || request.wrappedKeyIv() == null || request.wrappedKeyIv().isBlank()) {
                throw new BadRequestException(
                        "wrappedKey and wrappedKeyIv are required: wrap the item key with the collection key");
            }
            item.setCollectionId(request.collectionId());
            item.setCollectionWrappedKey(request.wrappedKey());
            item.setCollectionWrappedKeyIv(request.wrappedKeyIv());
            item.setItemType(ItemType.SHARED);
        }
        item = itemRepository.save(item);
        auditService.record(user.email(), AuditAction.ITEM_COLLECTION_CHANGED, item.getId(),
                item.getName(), null,
                request.collectionId() == null ? "removed from collection"
                        : "added to collection " + request.collectionId());
        return PasswordItemResponse.from(item, access.role(), wrappedKeyFor(user, id));
    }

    @Transactional
    public PasswordItemResponse create(CurrentUser user, PasswordItemRequest request) {
        if (request.syncMode() == SyncMode.LOCAL_ONLY) {
            throw new BadRequestException(
                    "Local-only items are never stored on the server; keep them on the device");
        }
        if (request.wrappedKey() == null || request.wrappedKey().isBlank()) {
            throw new BadRequestException("wrappedKey is required: wrap the item key with your public key");
        }
        PasswordItem item = new PasswordItem();
        apply(item, request);
        item.setOwnerEmail(user.email());
        item = itemRepository.save(item);
        itemKeyRepository.save(new ItemKey(item, user.email(), request.wrappedKey()));
        auditService.record(user.email(), AuditAction.ITEM_CREATED, item.getId(), item.getName(),
                null, "type=" + item.getItemType());
        return PasswordItemResponse.from(item, AccessRole.OWNER, request.wrappedKey());
    }

    @Transactional
    public PasswordItemResponse get(CurrentUser user, UUID id) {
        var access = readableItem(user, id);
        auditService.record(user.email(), AuditAction.ITEM_VIEWED, access.item().getId(),
                access.item().getName(), null, null);
        return PasswordItemResponse.from(access.item(), access.role(), wrappedKeyFor(user, id));
    }

    @Transactional
    public PasswordItemResponse update(CurrentUser user, UUID id, PasswordItemRequest request) {
        var access = readableItem(user, id);
        if (!access.role().canEdit()) {
            throw new ForbiddenException("Viewer role cannot modify this item");
        }
        PasswordItem item = access.item();
        if (request.syncMode() == SyncMode.LOCAL_ONLY) {
            throw new BadRequestException("Use the sync-mode endpoint to make an item local-only");
        }
        if (item.getItemType() == ItemType.SHARED && request.itemType() == ItemType.PERSONAL
                && (!permissionRepository.findByItemId(item.getId()).isEmpty()
                        || item.getCollectionId() != null)) {
            throw new BadRequestException("Revoke all access before making a shared item personal");
        }
        itemVersionRepository.save(new ItemVersion(item, user.email()));
        apply(item, request);
        item = itemRepository.save(item);
        auditService.record(user.email(), AuditAction.ITEM_UPDATED, item.getId(), item.getName(),
                null, null);
        return PasswordItemResponse.from(item, access.role(), wrappedKeyFor(user, id));
    }

    @Transactional
    public void delete(CurrentUser user, UUID id) {
        var access = readableItem(user, id);
        if (!access.role().isOwner()) {
            throw new ForbiddenException("Only the owner can delete an item");
        }
        permissionRepository.deleteByItemId(id);
        itemKeyRepository.deleteByItemId(id);
        itemVersionRepository.deleteByItemId(id);
        itemRepository.delete(access.item());
        auditService.record(user.email(), AuditAction.ITEM_DELETED, id, access.item().getName(),
                null, null);
    }

    /** Version history is ciphertext under the same item key, so anyone who can
     * read the item can also decrypt its history. */
    public List<ItemVersionResponse> versions(CurrentUser user, UUID id) {
        readableItem(user, id);
        return itemVersionRepository.findByItemIdOrderByReplacedAtDesc(id).stream()
                .map(ItemVersionResponse::from)
                .toList();
    }

    @Transactional
    public void recordCopy(CurrentUser user, UUID id) {
        var access = readableItem(user, id);
        auditService.record(user.email(), AuditAction.ITEM_COPIED, access.item().getId(),
                access.item().getName(), null, null);
    }

    /**
     * Toggling a personal item to LOCAL_ONLY removes it from the server: the
     * client keeps the (still encrypted) copy on the device. Shared items must
     * stay server-synced, otherwise sharing cannot work.
     */
    @Transactional
    public PasswordItemResponse changeSyncMode(CurrentUser user, UUID id, SyncMode syncMode) {
        var access = readableItem(user, id);
        if (!access.role().isOwner()) {
            throw new ForbiddenException("Only the owner can change sync mode");
        }
        PasswordItem item = access.item();
        if (syncMode == SyncMode.SERVER_SYNCED) {
            return PasswordItemResponse.from(item, access.role(), wrappedKeyFor(user, id));
        }
        if (item.getItemType() == ItemType.SHARED || item.getCollectionId() != null) {
            throw new BadRequestException("Shared items must stay server-synced");
        }
        PasswordItemResponse snapshot =
                PasswordItemResponse.from(item, access.role(), wrappedKeyFor(user, id));
        auditService.record(user.email(), AuditAction.SYNC_MODE_CHANGED, item.getId(),
                item.getName(), null, "SERVER_SYNCED -> LOCAL_ONLY, server copy removed");
        permissionRepository.deleteByItemId(id);
        itemKeyRepository.deleteByItemId(id);
        itemVersionRepository.deleteByItemId(id);
        itemRepository.delete(item);
        return new PasswordItemResponse(snapshot.id(), snapshot.name(), snapshot.url(),
                snapshot.username(), snapshot.encryptedPassword(), snapshot.passwordIv(),
                snapshot.encryptedNotes(), snapshot.notesIv(), snapshot.tags(),
                snapshot.ownerEmail(), snapshot.type(), snapshot.itemType(), SyncMode.LOCAL_ONLY,
                snapshot.accessRole(), snapshot.wrappedKey(), null, null, null,
                snapshot.createdAt(), snapshot.updatedAt());
    }

    /**
     * Rotates the item's AES key (crypto-shredding): the caller has already
     * re-encrypted password/notes with a fresh key and re-wrapped that key for
     * every remaining holder (owner included). All old {@link ItemKey} rows are
     * replaced, so anyone not in the new list — typically the recipient whose
     * access is being revoked — cannot decrypt anything written from now on.
     */
    @Transactional
    public PasswordItemResponse rotateKey(CurrentUser user, UUID id, RotateKeyRequest request) {
        var access = readableItem(user, id);
        if (!access.role().isOwner()) {
            throw new ForbiddenException("Only the owner can rotate the item key");
        }
        if (access.item().getCollectionId() != null) {
            // Item keys of collection items are wrapped by the collection key, not
            // per-recipient; rotate the collection key instead (see CollectionService).
            throw new BadRequestException("Rotate the collection key instead for items in a collection");
        }
        boolean ownerIncluded = request.wrappedKeys().stream()
                .anyMatch(entry -> entry.granteeEmail().equalsIgnoreCase(user.email()));
        if (!ownerIncluded) {
            throw new BadRequestException("The rotated key must be wrapped for the owner too");
        }
        PasswordItem item = access.item();
        item.setEncryptedPassword(request.encryptedPassword());
        item.setPasswordIv(request.passwordIv());
        item.setEncryptedNotes(request.encryptedNotes());
        item.setNotesIv(request.notesIv());
        item = itemRepository.save(item);

        itemKeyRepository.deleteByItemId(id);
        // Force the deletes to hit the DB before the inserts below: Hibernate's
        // default flush order (inserts, then deletes) would otherwise violate the
        // (item_id, userEmail) unique constraint whenever a holder — e.g. the
        // owner — appears in both the old and the new key list.
        itemKeyRepository.flush();
        for (RotateKeyRequest.WrappedKeyEntry entry : request.wrappedKeys()) {
            itemKeyRepository.save(new ItemKey(item, entry.granteeEmail().toLowerCase(Locale.ROOT),
                    entry.wrappedKey()));
        }

        auditService.record(user.email(), AuditAction.ITEM_KEY_ROTATED, item.getId(), item.getName(),
                null, "key rotated for " + request.wrappedKeys().size() + " holder(s)");
        return PasswordItemResponse.from(item, access.role(), wrappedKeyFor(user, id));
    }

    private String wrappedKeyFor(CurrentUser user, UUID itemId) {
        return itemKeyRepository.findByItemIdAndUserEmail(itemId, user.email())
                .map(ItemKey::getWrappedKey)
                .orElse(null);
    }

    private ItemAccess readableItem(CurrentUser user, UUID id) {
        PasswordItem item = itemRepository.findById(id)
                .orElseThrow(() -> new NotFoundException("Item not found"));
        AccessRole role = sharingService.resolveAccess(item, user);
        if (!role.canRead()) {
            // Hide the item's existence from users without access.
            throw new NotFoundException("Item not found");
        }
        return new ItemAccess(item, role);
    }

    private static void apply(PasswordItem item, PasswordItemRequest request) {
        item.setName(request.name());
        item.setUrl(request.url());
        item.setUsername(request.username());
        item.setEncryptedPassword(request.encryptedPassword());
        item.setPasswordIv(request.passwordIv());
        item.setEncryptedNotes(request.encryptedNotes());
        item.setNotesIv(request.notesIv());
        item.setTags(request.tags());
        // Old API clients predate templates; migrate their semantics to LOGIN.
        item.setType(request.type() == null ? SecretType.LOGIN : request.type());
        item.setItemType(request.itemType());
        item.setSyncMode(SyncMode.SERVER_SYNCED);
    }

    private record ItemAccess(PasswordItem item, AccessRole role) {
    }
}
