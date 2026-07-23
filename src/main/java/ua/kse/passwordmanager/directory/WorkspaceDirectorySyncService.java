package ua.kse.passwordmanager.directory;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ua.kse.passwordmanager.common.BadGatewayException;

/** Materializes Google Workspace, keeping local governance decisions intact. */
@Service
public class WorkspaceDirectorySyncService {
    private static final Logger log = LoggerFactory.getLogger(WorkspaceDirectorySyncService.class);
    private final WorkspaceDirectoryClient directory;
    private final WorkspaceUserRepository users;
    private final WorkspaceGroupRepository groups;
    private final WorkspaceMembershipRepository memberships;

    public WorkspaceDirectorySyncService(WorkspaceDirectoryClient directory, WorkspaceUserRepository users,
            WorkspaceGroupRepository groups, WorkspaceMembershipRepository memberships) {
        this.directory = directory; this.users = users; this.groups = groups; this.memberships = memberships;
    }

    /** Runs every 15 minutes. The unavailable client deliberately does no work
     * in installations that have not mounted Directory credentials yet. */
    @Scheduled(fixedDelayString = "${pm.google-workspace.sync-interval-ms:900000}")
    @Transactional
    public void scheduledSync() {
        try {
            SyncResult result = sync();
            log.info("Workspace directory sync: {} users, {} groups, {} memberships",
                    result.users(), result.groups(), result.memberships());
        } catch (BadGatewayException e) {
            // Swallowed so a Directory outage never wipes local governance state,
            // but never silently: without this line a misconfigured deployment
            // just looks like "users are not provisioned" with no trace at all.
            log.warn("Workspace directory sync failed; local governance state left unchanged: {}",
                    rootCauseMessage(e), e);
        }
    }

    private static String rootCauseMessage(Throwable failure) {
        Throwable cause = failure;
        while (cause.getCause() != null && cause.getCause() != cause) cause = cause.getCause();
        return cause.getMessage() == null ? cause.getClass().getSimpleName() : cause.getMessage();
    }

    @Transactional
    public SyncResult sync() {
        // Fetch the complete snapshot before changing local state. A failed
        // page/membership request must never make valid principals disappear.
        var sourceUsers = directory.listUsers();
        var sourceGroups = directory.listGroups();
        var membershipsByGroup = new LinkedHashMap<String, Set<String>>();
        for (DirectoryGroup source : sourceGroups) {
            membershipsByGroup.put(source.email().toLowerCase(Locale.ROOT),
                    new HashSet<>(directory.memberEmails(source.id())));
        }
        Set<String> presentUsers = sourceUsers.stream().map(u -> u.email().toLowerCase(Locale.ROOT)).collect(java.util.stream.Collectors.toSet());
        Set<String> presentGroups = new HashSet<>(membershipsByGroup.keySet());
        for (DirectoryUser source : sourceUsers) {
            WorkspaceUser user = users.findById(source.email().toLowerCase(Locale.ROOT))
                    .orElseGet(() -> new WorkspaceUser(source.email().toLowerCase(Locale.ROOT)));
            user.updateFromGoogle(source);
            users.save(user);
        }
        users.findAll().stream().filter(user -> !presentUsers.contains(user.getEmail()))
                .forEach(user -> { user.setDirectoryPresent(false); users.save(user); });
        int membershipCount = 0;
        for (DirectoryGroup source : sourceGroups) {
            String groupEmail = source.email().toLowerCase(Locale.ROOT);
            // New groups deliberately start hidden. V12 seeds referenced legacy
            // groups as visible, and sync never changes that administrator choice.
            WorkspaceGroup group = groups.findById(groupEmail).orElseGet(() -> new WorkspaceGroup(groupEmail, false));
            group.updateFromGoogle(source);
            groups.save(group);
            Set<String> current = membershipsByGroup.get(groupEmail);
            memberships.deleteByGroupEmail(groupEmail);
            for (String member : current) {
                memberships.save(new WorkspaceMembership(groupEmail, member.toLowerCase(Locale.ROOT)));
                membershipCount++;
            }
        }
        groups.findAll().stream().filter(group -> !presentGroups.contains(group.getEmail())).forEach(group -> {
            group.setDirectoryPresent(false);
            groups.save(group);
            memberships.deleteByGroupEmail(group.getEmail());
        });
        return new SyncResult(sourceUsers.size(), sourceGroups.size(), membershipCount);
    }

    public record SyncResult(int users, int groups, int memberships) {}
}
