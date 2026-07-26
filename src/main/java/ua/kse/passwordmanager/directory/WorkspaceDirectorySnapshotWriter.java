package ua.kse.passwordmanager.directory;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The transactional write half of the directory sync: fetches a complete
 * Workspace projection and swaps the local snapshot to match it.
 *
 * <p>Deliberately a separate bean from {@link WorkspaceDirectorySyncService}.
 * The whole swap has to be one transaction — a group's memberships are deleted
 * and re-inserted, and a partial swap is worse than a stale snapshot — and
 * {@code @Transactional} only applies when the call arrives through Spring's
 * proxy. While this lived on the scheduler's own bean, {@code scheduledSync()}
 * reached it by plain self-invocation, the annotation never took effect, and
 * every pass died at the first bulk delete with TransactionRequiredException.
 * Keeping the two halves in separate beans makes that mistake unavailable
 * rather than merely fixed.
 */
@Service
public class WorkspaceDirectorySnapshotWriter {

    private static final Logger log = LoggerFactory.getLogger(WorkspaceDirectorySnapshotWriter.class);

    private final WorkspaceDirectoryClient directory;
    private final WorkspaceUserRepository users;
    private final WorkspaceGroupRepository groups;
    private final WorkspaceMembershipRepository memberships;

    public WorkspaceDirectorySnapshotWriter(WorkspaceDirectoryClient directory, WorkspaceUserRepository users,
            WorkspaceGroupRepository groups, WorkspaceMembershipRepository memberships) {
        this.directory = directory;
        this.users = users;
        this.groups = groups;
        this.memberships = memberships;
    }

    @Transactional
    public SyncResult sync() {
        // Fetch the complete snapshot before changing local state. A failed
        // page/membership request must never make valid principals disappear.
        var sourceUsers = directory.listUsers();
        var sourceGroups = directory.listGroups();
        // A client that answers with an empty projection instead of throwing
        // would otherwise mark the entire local Workspace snapshot absent and
        // drop every materialized membership — the same damage as a wipe, minus
        // the error. No real Workspace domain has zero users.
        if (sourceUsers.isEmpty()) {
            log.warn("Workspace directory returned no users; skipping sync to protect local governance state");
            return new SyncResult(0, 0, 0);
        }
        boolean groupsReadable = !sourceGroups.isEmpty() || groups.count() == 0;
        var membershipsByGroup = new LinkedHashMap<String, Set<String>>();
        for (DirectoryGroup source : sourceGroups) {
            // Normalize case before de-duplicating: Google occasionally returns the
            // same member with inconsistent casing, and HashSet dedupes by exact
            // string, so lowering case only at save time let case-variant
            // duplicates slip through and collide on the (group_email,
            // member_email) unique constraint mid-transaction.
            Set<String> normalizedMembers = new HashSet<>();
            for (String member : directory.memberEmails(source.id())) {
                normalizedMembers.add(member.toLowerCase(Locale.ROOT));
            }
            membershipsByGroup.put(source.email().toLowerCase(Locale.ROOT), normalizedMembers);
        }
        Set<String> presentUsers = sourceUsers.stream().map(u -> u.email().toLowerCase(Locale.ROOT))
                .collect(java.util.stream.Collectors.toSet());
        Set<String> presentGroups = new HashSet<>(membershipsByGroup.keySet());
        for (DirectoryUser source : sourceUsers) {
            WorkspaceUser user = users.findById(source.email().toLowerCase(Locale.ROOT))
                    .orElseGet(() -> new WorkspaceUser(source.email().toLowerCase(Locale.ROOT)));
            user.updateFromGoogle(source);
            syncAvatar(user, source);
            users.save(user);
        }
        users.findAll().stream().filter(user -> !presentUsers.contains(user.getEmail()))
                .forEach(user -> { user.setDirectoryPresent(false); users.save(user); });
        int membershipCount = 0;
        for (DirectoryGroup source : sourceGroups) {
            String groupEmail = source.email().toLowerCase(Locale.ROOT);
            // New groups start visible by default; sync never overwrites an
            // administrator's existing visibility choice for a known group.
            WorkspaceGroup group = groups.findById(groupEmail).orElseGet(() -> new WorkspaceGroup(groupEmail, true));
            group.updateFromGoogle(source);
            groups.save(group);
            Set<String> current = membershipsByGroup.get(groupEmail);
            memberships.deleteByGroupEmail(groupEmail);
            for (String member : current) {
                memberships.save(new WorkspaceMembership(groupEmail, member.toLowerCase(Locale.ROOT)));
                membershipCount++;
            }
        }
        // Only retire local groups when the group projection was actually
        // readable; an empty listGroups() against a populated local snapshot is
        // a failed read, not a domain that lost all of its groups.
        if (!groupsReadable) {
            log.warn("Workspace directory returned no groups while {} are materialized locally; "
                    + "keeping them and their memberships", groups.count());
            return new SyncResult(sourceUsers.size(), 0, membershipCount);
        }
        groups.findAll().stream().filter(group -> !presentGroups.contains(group.getEmail())).forEach(group -> {
            group.setDirectoryPresent(false);
            groups.save(group);
            memberships.deleteByGroupEmail(group.getEmail());
        });
        return new SyncResult(sourceUsers.size(), sourceGroups.size(), membershipCount);
    }

    /**
     * Materializes the Google profile photo, but only when its etag moved — one
     * extra Directory call per changed photo instead of one per user per pass.
     * A photo download failure must not abort the whole snapshot, so it keeps the
     * previously stored image.
     */
    private void syncAvatar(WorkspaceUser user, DirectoryUser source) {
        String etag = source.photoEtag();
        if (etag == null || etag.isBlank()) {
            if (user.getAvatarDataUrl() != null) user.clearAvatar();
            return;
        }
        if (!user.needsAvatarRefresh(etag)) return;
        try {
            directory.userPhotoDataUrl(user.getEmail())
                    .ifPresentOrElse(dataUrl -> user.setAvatar(dataUrl, etag), user::clearAvatar);
        } catch (RuntimeException e) {
            log.warn("Could not fetch the Google profile photo for {}; keeping the stored copy: {}",
                    user.getEmail(), e.getMessage());
        }
    }

    public record SyncResult(int users, int groups, int memberships) {}
}
