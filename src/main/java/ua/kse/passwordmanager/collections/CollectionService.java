package ua.kse.passwordmanager.collections;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ua.kse.passwordmanager.audit.AuditAction;
import ua.kse.passwordmanager.audit.AuditService;
import ua.kse.passwordmanager.auth.CurrentUser;
import ua.kse.passwordmanager.collections.CollectionDtos.AddMemberRequest;
import ua.kse.passwordmanager.collections.CollectionDtos.CollectionResponse;
import ua.kse.passwordmanager.collections.CollectionDtos.CreateCollectionRequest;
import ua.kse.passwordmanager.collections.CollectionDtos.MemberResponse;
import ua.kse.passwordmanager.common.BadRequestException;
import ua.kse.passwordmanager.common.ForbiddenException;
import ua.kse.passwordmanager.common.NotFoundException;
import ua.kse.passwordmanager.directory.DirectoryPrincipal;
import ua.kse.passwordmanager.directory.WorkspaceDirectoryClient;
import ua.kse.passwordmanager.vault.PasswordItem;
import ua.kse.passwordmanager.vault.PasswordItemRepository;

@Service
public class CollectionService {

    private final CollectionRepository collectionRepository;
    private final CollectionMemberRepository memberRepository;
    private final PasswordItemRepository itemRepository;
    private final AuditService auditService;
    private final WorkspaceDirectoryClient directory;
    private final CollectionGroupService groupService;

    public CollectionService(CollectionRepository collectionRepository,
                             CollectionMemberRepository memberRepository,
                             PasswordItemRepository itemRepository,
                             AuditService auditService, WorkspaceDirectoryClient directory,
                             CollectionGroupService groupService) {
        this.collectionRepository = collectionRepository;
        this.memberRepository = memberRepository;
        this.itemRepository = itemRepository;
        this.auditService = auditService;
        this.directory = directory;
        this.groupService = groupService;
    }

    @Transactional
    public CollectionResponse create(CurrentUser user, CreateCollectionRequest request) {
        String group = normalizedOptional(request.directoryGroup());
        if (group != null && !groupService.exists(group)) {
            throw new BadRequestException("Group does not exist in Google Workspace");
        }
        // The picker already omits hidden groups, but the API must enforce the
        // administrator's visibility decision on its own.
        if (group != null && !user.isAdmin() && !groupService.isVisibleToUsers(group)) {
            throw new ForbiddenException("This Google Workspace group is not available for collections");
        }
        Collection collection = collectionRepository.save(
                new Collection(request.name().trim(), user.email(), group));
        CollectionMember self = memberRepository.save(new CollectionMember(
                collection, user.email(), CollectionRole.MANAGER,
                request.wrappedKeyForSelf(), user.email()));
        auditService.record(user.email(), AuditAction.COLLECTION_CREATED, collection.getId(),
                collection.getName(), null, null);
        return response(collection, self);
    }

    @Transactional(readOnly = true)
    public List<CollectionResponse> listMine(CurrentUser user) {
        return memberRepository.findByMemberEmail(user.email()).stream()
                .filter(member -> member.getStatus().hasCryptographicAccess())
                .map(member -> response(member.getCollection(), member))
                .toList();
    }

    public List<MemberResponse> members(CurrentUser user, UUID collectionId) {
        requireMembership(user, collectionId);
        return memberRepository.findByCollectionId(collectionId).stream()
                .map(MemberResponse::from)
                .toList();
    }

    /**
     * Looks up a Workspace group only after authorizing the manager. The returned
     * emails are suggestions: adding each one still requires client-side key
     * wrapping in {@link #addMember(CurrentUser, UUID, AddMemberRequest)}.
     */
    @Transactional(readOnly = true)
    public List<String> directorySuggestions(CurrentUser user, UUID collectionId, String group) {
        CollectionMember me = requireMembership(user, collectionId);
        if (!me.getRole().canManageMembers()) {
            throw new ForbiddenException("Only a manager can request member suggestions");
        }
        String normalizedGroup = normalizedOptional(group);
        if (normalizedGroup == null) {
            throw new BadRequestException("group is required");
        }
        if (!normalizedGroup.equals(me.getCollection().getDirectoryGroup()) || !groupService.exists(normalizedGroup)) {
            throw new BadRequestException("group is not configured for this collection");
        }
        var existing = memberRepository.findByCollectionId(collectionId).stream()
                .map(member -> member.getMemberEmail().toLowerCase(Locale.ROOT))
                .collect(Collectors.toSet());
        return directory.memberEmails(normalizedGroup).stream()
                .map(email -> email.toLowerCase(Locale.ROOT))
                .filter(email -> !existing.contains(email))
                .distinct()
                .sorted()
                .toList();
    }

    @Transactional
    public void syncGroup(CurrentUser user, UUID collectionId) {
        CollectionMember me = requireMembership(user, collectionId);
        if (!me.getRole().canManageMembers()) throw new ForbiddenException("Only a manager can sync group membership");
        if (me.getCollection().getDirectoryGroup() == null) throw new BadRequestException("Collection has no Workspace group");
        groupService.sync(me.getCollection(), user.email());
    }

    @Transactional
    public MemberResponse addMember(CurrentUser user, UUID collectionId, AddMemberRequest request) {
        CollectionMember me = requireMembership(user, collectionId);
        if (!me.getRole().canManageMembers()) {
            throw new ForbiddenException("Only a manager can add members");
        }
        Collection collection = me.getCollection();
        String email = request.email().trim().toLowerCase(Locale.ROOT);
        CollectionMember member = memberRepository
                .findByCollectionIdAndMemberEmail(collectionId, email)
                .map(existing -> {
                    existing.setRole(request.role());
                    existing.setWrappedKey(request.wrappedKey());
                    return existing;
                })
                .orElseGet(() -> new CollectionMember(collection, email, request.role(),
                        request.wrappedKey(), user.email()));
        member = memberRepository.save(member);
        auditService.record(user.email(), AuditAction.COLLECTION_MEMBER_ADDED, collectionId,
                collection.getName(), email, "role " + request.role());
        return MemberResponse.from(member);
    }

    @Transactional
    public MemberResponse changeRole(CurrentUser user, UUID collectionId, UUID memberId,
                                     CollectionRole role) {
        CollectionMember me = requireMembership(user, collectionId);
        if (!me.getRole().canManageMembers()) {
            throw new ForbiddenException("Only a manager can change roles");
        }
        CollectionMember member = memberRepository.findByIdAndCollectionId(memberId, collectionId)
                .orElseThrow(() -> new NotFoundException("Member not found"));
        if (member.getMemberEmail().equalsIgnoreCase(me.getCollection().getOwnerEmail())) {
            throw new BadRequestException("The collection owner's role cannot be changed");
        }
        member.setRole(role);
        auditService.record(user.email(), AuditAction.COLLECTION_MEMBER_ROLE_CHANGED, collectionId,
                me.getCollection().getName(), member.getMemberEmail(), "role " + role);
        return MemberResponse.from(memberRepository.save(member));
    }

    /** The manager client rotates the collection key before calling this endpoint. */
    @Transactional
    public void removeMember(CurrentUser user, UUID collectionId, UUID memberId) {
        CollectionMember me = requireMembership(user, collectionId);
        if (!me.getRole().canManageMembers()) {
            throw new ForbiddenException("Only a manager can remove members");
        }
        CollectionMember member = memberRepository.findByIdAndCollectionId(memberId, collectionId)
                .orElseThrow(() -> new NotFoundException("Member not found"));
        if (member.getMemberEmail().equalsIgnoreCase(me.getCollection().getOwnerEmail())) {
            throw new BadRequestException("The collection owner cannot be removed");
        }
        memberRepository.delete(member);
        auditService.record(user.email(), AuditAction.COLLECTION_MEMBER_REMOVED, collectionId,
                me.getCollection().getName(), member.getMemberEmail(), null);
    }

    /**
     * Rotates the collection's AES key (crypto-shredding): the caller has
     * already generated a fresh key, re-wrapped it for every member who keeps
     * access, and re-wrapped every item's (unchanged) item key with the new
     * collection key. Members not listed in memberWrappedKeys — typically the
     * one being removed — lose the ability to decrypt anything from now on.
     */
    @Transactional
    public void rotateKey(CurrentUser user, UUID collectionId, RotateCollectionKeyRequest request) {
        CollectionMember me = requireMembership(user, collectionId);
        if (!me.getRole().canManageMembers()) {
            throw new ForbiddenException("Only a manager can rotate the collection key");
        }
        Collection collection = me.getCollection();

        for (RotateCollectionKeyRequest.MemberKeyEntry entry : request.memberWrappedKeys()) {
            CollectionMember member = memberRepository.findByIdAndCollectionId(entry.memberId(), collectionId)
                    .orElseThrow(() -> new NotFoundException("Member not found"));
            if (!member.getStatus().hasCryptographicAccess()) {
                throw new BadRequestException("Pending member cannot receive a rotated collection key");
            }
            member.setWrappedKey(entry.wrappedKey());
            memberRepository.save(member);
        }

        for (RotateCollectionKeyRequest.ItemKeyEntry entry : request.itemWrappedKeys()) {
            PasswordItem item = itemRepository.findById(entry.itemId())
                    .orElseThrow(() -> new NotFoundException("Item not found"));
            if (!collectionId.equals(item.getCollectionId())) {
                throw new BadRequestException("Item does not belong to this collection");
            }
            item.setCollectionWrappedKey(entry.wrappedKey());
            item.setCollectionWrappedKeyIv(entry.wrappedKeyIv());
            itemRepository.save(item);
        }

        auditService.record(user.email(), AuditAction.COLLECTION_KEY_ROTATED, collectionId,
                collection.getName(), null,
                "rotated for " + request.memberWrappedKeys().size() + " member(s), "
                        + request.itemWrappedKeys().size() + " item(s)");
    }

    @Transactional
    public void delete(CurrentUser user, UUID collectionId) {
        Collection collection = collectionRepository.findById(collectionId)
                .orElseThrow(() -> new NotFoundException("Collection not found"));
        if (!collection.getOwnerEmail().equalsIgnoreCase(user.email())) {
            throw new ForbiddenException("Only the owner can delete a collection");
        }
        if (itemRepository.countByCollectionId(collectionId) > 0) {
            throw new BadRequestException("Remove all items from the collection first");
        }
        memberRepository.deleteByCollectionId(collectionId);
        collectionRepository.delete(collection);
        auditService.record(user.email(), AuditAction.COLLECTION_DELETED, collectionId,
                collection.getName(), null, null);
    }

    public Optional<CollectionRole> roleFor(UUID collectionId, String email) {
        return memberRepository.findByCollectionIdAndMemberEmail(collectionId, email)
                .filter(member -> member.getStatus().hasCryptographicAccess())
                .map(CollectionMember::getRole);
    }

    /** collectionId → role for every collection the user belongs to. */
    @Transactional(readOnly = true)
    public Map<UUID, CollectionRole> membershipsOf(String email) {
        return memberRepository.findByMemberEmail(email).stream()
                .filter(member -> member.getStatus().hasCryptographicAccess())
                .collect(Collectors.toMap(m -> m.getCollection().getId(), CollectionMember::getRole));
    }

    private CollectionMember requireMembership(CurrentUser user, UUID collectionId) {
        collectionRepository.findById(collectionId)
                .orElseThrow(() -> new NotFoundException("Collection not found"));
        return memberRepository.findByCollectionIdAndMemberEmail(collectionId, user.email())
                .filter(member -> member.getStatus().hasCryptographicAccess())
                // Hide the collection's existence from non-members.
                .orElseThrow(() -> new NotFoundException("Collection not found"));
    }

    private static String normalizedOptional(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    private CollectionResponse response(Collection collection, CollectionMember me) {
        List<CollectionMember> all = memberRepository.findByCollectionId(collection.getId());
        return CollectionResponse.from(collection, me,
                (int) all.stream().filter(member -> member.getStatus().hasCryptographicAccess()).count(),
                (int) all.stream().filter(member -> member.getStatus() == CollectionMemberStatus.PENDING_PROVISIONING).count(),
                (int) all.stream().filter(member -> member.getStatus() == CollectionMemberStatus.PENDING_REMOVAL).count());
    }
}
