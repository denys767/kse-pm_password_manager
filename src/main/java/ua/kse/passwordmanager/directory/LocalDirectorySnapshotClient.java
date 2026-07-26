package ua.kse.passwordmanager.directory;

import java.util.List;
import java.util.Locale;
import java.util.Optional;
import org.springframework.data.domain.PageRequest;
import ua.kse.passwordmanager.common.BadGatewayException;
import ua.kse.passwordmanager.keys.UserKeysRepository;

/**
 * Answers interactive directory lookups from the materialized Workspace
 * snapshot instead of Google.
 *
 * <p>The snapshot is the same data the synchronizer already wrote, so serving
 * autocomplete and share validation from it during a Google outage is not a
 * weaker answer — it is a slightly older one. Refusing instead (which is what
 * used to happen) means nobody can share anything for as long as Google, the
 * network or the credential is unhappy.
 *
 * <p>It deliberately cannot act as a sync source: {@link #listUsers()} and
 * friends throw, so a degraded read can never be mistaken for a fresh
 * projection and overwrite the snapshot with itself.
 */
class LocalDirectorySnapshotClient implements WorkspaceDirectoryClient {

    private final WorkspaceUserRepository users;
    private final WorkspaceGroupRepository groups;
    private final WorkspaceMembershipRepository memberships;
    private final UserKeysRepository keys;

    LocalDirectorySnapshotClient(WorkspaceUserRepository users, WorkspaceGroupRepository groups,
            WorkspaceMembershipRepository memberships, UserKeysRepository keys) {
        this.users = users; this.groups = groups; this.memberships = memberships; this.keys = keys;
    }

    @Override
    public List<DirectoryPrincipal> search(String query, List<DirectoryPrincipal.Type> types, int limit) {
        String term = query == null ? "" : query.trim();
        List<DirectoryPrincipal> found = new java.util.ArrayList<>();
        if (types.contains(DirectoryPrincipal.Type.USER)) {
            users.findByEmailContainingIgnoreCaseOrDisplayNameContainingIgnoreCase(term, term,
                            PageRequest.of(0, Math.max(1, limit)))
                    .stream()
                    .filter(WorkspaceUser::isDirectoryPresent)
                    .filter(WorkspaceUser::hasEffectiveAccess)
                    .map(this::principal)
                    .forEach(found::add);
        }
        if (types.contains(DirectoryPrincipal.Type.GROUP)) {
            groups.findByEmailContainingIgnoreCaseOrDisplayNameContainingIgnoreCase(term, term,
                            PageRequest.of(0, Math.max(1, limit)))
                    .stream()
                    .filter(WorkspaceGroup::isDirectoryPresent)
                    .map(this::principal)
                    .forEach(found::add);
        }
        return found;
    }

    @Override
    public Optional<DirectoryPrincipal> find(DirectoryPrincipal.Type type, String id) {
        String key = id == null ? "" : id.trim().toLowerCase(Locale.ROOT);
        if (type == DirectoryPrincipal.Type.USER) {
            return users.findById(key)
                    .or(() -> users.findAll().stream().filter(u -> key.equals(u.getDirectoryId())).findFirst())
                    .filter(WorkspaceUser::isDirectoryPresent)
                    .map(this::principal);
        }
        return group(key).filter(WorkspaceGroup::isDirectoryPresent).map(this::principal);
    }

    @Override
    public List<String> memberEmails(String groupId) {
        // Callers hold Google's immutable group id; the snapshot is keyed by email.
        return group(groupId == null ? "" : groupId.trim().toLowerCase(Locale.ROOT))
                .map(group -> memberships.findByGroupEmail(group.getEmail()).stream()
                        .map(WorkspaceMembership::getMemberEmail).toList())
                .orElseGet(List::of);
    }

    private Optional<WorkspaceGroup> group(String key) {
        return groups.findById(key)
                .or(() -> groups.findAll().stream().filter(g -> key.equals(g.getDirectoryId())).findFirst());
    }

    private DirectoryPrincipal principal(WorkspaceUser user) {
        return new DirectoryPrincipal(DirectoryPrincipal.Type.USER,
                user.getDirectoryId() == null ? user.getEmail() : user.getDirectoryId(),
                user.getEmail(), user.getDisplayName(), keys.existsById(user.getEmail()), null, true,
                user.getAvatarDataUrl());
    }

    private DirectoryPrincipal principal(WorkspaceGroup group) {
        return new DirectoryPrincipal(DirectoryPrincipal.Type.GROUP,
                group.getDirectoryId() == null ? group.getEmail() : group.getDirectoryId(),
                group.getEmail(), group.getDisplayName(), false,
                (long) memberships.findByGroupEmail(group.getEmail()).size(), group.isVisibleToUsers(), null);
    }

    private BadGatewayException notASyncSource() {
        return new BadGatewayException("Google Workspace Directory is temporarily unavailable");
    }

    @Override public List<DirectoryUser> listUsers() { throw notASyncSource(); }
    @Override public List<DirectoryGroup> listGroups() { throw notASyncSource(); }
    @Override public Optional<String> userPhotoDataUrl(String userKey) { throw notASyncSource(); }
}
