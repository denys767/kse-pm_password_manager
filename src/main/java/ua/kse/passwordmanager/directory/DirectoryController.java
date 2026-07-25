package ua.kse.passwordmanager.directory;

import java.util.Arrays;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import ua.kse.passwordmanager.auth.AuthFacade;

@RestController
@RequestMapping("/api/directory")
public class DirectoryController {
    private final WorkspaceDirectoryClient directory;
    private final WorkspaceGroupRepository groups;
    private final WorkspaceUserRepository users;
    private final AuthFacade auth;
    public DirectoryController(WorkspaceDirectoryClient directory, WorkspaceGroupRepository groups,
            WorkspaceUserRepository users, AuthFacade auth) {
        this.directory = directory; this.groups = groups; this.users = users; this.auth = auth;
    }
    @GetMapping("/principals")
    public List<DirectoryPrincipal> principals(@RequestParam(defaultValue = "") String query,
            @RequestParam(defaultValue = "USER,GROUP") String types) {
        List<DirectoryPrincipal.Type> requested = Arrays.stream(types.split(",")).map(String::trim)
                .filter(s -> !s.isBlank()).map(String::toUpperCase).map(DirectoryPrincipal.Type::valueOf).toList();
        boolean admin = auth.current().isAdmin();
        return directory.search(query, requested, 50).stream()
                .map(this::withVisibility)
                // Non-admins never see a hidden group at all; admins see every group,
                // with visibleToUsers letting the UI mark the hidden ones explicitly.
                .filter(principal -> principal.type() != DirectoryPrincipal.Type.GROUP || admin || principal.visibleToUsers())
                // Avatars come from the local snapshot: the picker fires on every
                // keystroke, and a photo round-trip per suggestion would both be
                // slow and burn Directory quota.
                .map(this::withAvatar)
                .toList();
    }

    /** Governance state lives locally, not in the Directory response. */
    private DirectoryPrincipal withVisibility(DirectoryPrincipal principal) {
        if (principal.type() != DirectoryPrincipal.Type.GROUP) return principal;
        boolean visible = groups.findById(principal.email().toLowerCase())
                .map(WorkspaceGroup::isVisibleToUsers).orElse(false);
        return new DirectoryPrincipal(principal.type(), principal.id(), principal.email(),
                principal.displayName(), principal.vaultKeyAvailable(), principal.memberCount(),
                visible, principal.avatarDataUrl());
    }

    private DirectoryPrincipal withAvatar(DirectoryPrincipal principal) {
        if (principal.type() != DirectoryPrincipal.Type.USER) return principal;
        return users.findById(principal.email().toLowerCase())
                .map(WorkspaceUser::getAvatarDataUrl)
                .map(principal::withAvatar)
                .orElse(principal);
    }
}
