package ua.kse.passwordmanager.collections;

import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ua.kse.passwordmanager.directory.DirectoryPrincipal;
import ua.kse.passwordmanager.directory.WorkspaceDirectoryClient;
import ua.kse.passwordmanager.audit.AuditAction;
import ua.kse.passwordmanager.audit.AuditService;

@Service
public class CollectionGroupService {
    private final WorkspaceDirectoryClient directory;
    private final CollectionRepository collections;
    private final CollectionMemberRepository members;
    private final AuditService audit;

    public CollectionGroupService(WorkspaceDirectoryClient directory,
                                  CollectionRepository collections, CollectionMemberRepository members,
                                  AuditService audit) {
        this.directory = directory;
        this.collections = collections;
        this.members = members;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public List<String> available() {
        return directory.search("", List.of(DirectoryPrincipal.Type.GROUP), 100).stream().map(DirectoryPrincipal::email).toList();
    }

    /** True when the group still exists in Google Workspace. */
    @Transactional(readOnly = true)
    public boolean exists(String rawName) {
        return rawName != null && !rawName.isBlank()
                && directory.find(DirectoryPrincipal.Type.GROUP, rawName.trim()).isPresent();
    }

    /** Records group changes, but never wraps or exposes a collection key. */
    @Transactional
    public void sync(Collection collection, String actor) {
        String group = collection.getDirectoryGroup();
        if (group == null) return;
        Set<String> groupMembers = directory.memberEmails(group).stream()
                .map(email -> email.trim().toLowerCase(Locale.ROOT))
                .filter(email -> !email.isBlank())
                .collect(Collectors.toSet());
        List<CollectionMember> existing = members.findByCollectionId(collection.getId());
        Set<String> existingEmails = existing.stream().map(CollectionMember::getMemberEmail)
                .map(email -> email.toLowerCase(Locale.ROOT)).collect(Collectors.toSet());
        for (String email : groupMembers) {
            if (!existingEmails.contains(email)) {
                members.save(CollectionMember.pending(collection, email, actor));
                audit.record(actor, AuditAction.COLLECTION_MEMBER_PENDING, collection.getId(), collection.getName(), email,
                        "Google Workspace group member awaiting manager client-side key wrapping");
            }
        }
        for (CollectionMember member : existing) {
            if (member.getMemberEmail().equalsIgnoreCase(collection.getOwnerEmail()) ||
                    groupMembers.contains(member.getMemberEmail().toLowerCase(Locale.ROOT))) continue;
            if (member.getStatus() == CollectionMemberStatus.PENDING_PROVISIONING) {
                members.delete(member);
                audit.record(actor, AuditAction.COLLECTION_MEMBER_AUTO_REMOVED, collection.getId(), collection.getName(),
                        member.getMemberEmail(), "left group before provisioning");
            } else if (member.getStatus() == CollectionMemberStatus.ACTIVE) {
                member.setStatus(CollectionMemberStatus.PENDING_REMOVAL);
                members.save(member);
                audit.record(actor, AuditAction.COLLECTION_MEMBER_AUTO_REMOVED, collection.getId(), collection.getName(),
                        member.getMemberEmail(), "key rotation required before removal");
            }
        }
        audit.record(actor, AuditAction.COLLECTION_SYNC, collection.getId(), collection.getName(), group, null);
    }

    @Scheduled(fixedDelayString = "${pm.collection-group-sync-delay-ms:300000}")
    public void syncAllManagedCollections() {
        for (Collection collection : collections.findByDirectoryGroupIsNotNull()) {
            try { sync(collection, "system:collection-group-sync"); }
            catch (RuntimeException ignored) { /* next scheduled pass retries without changing local membership */ }
        }
    }
}
