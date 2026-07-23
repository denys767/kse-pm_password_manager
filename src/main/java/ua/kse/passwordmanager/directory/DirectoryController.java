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
    private final AuthFacade auth;
    public DirectoryController(WorkspaceDirectoryClient directory, WorkspaceGroupRepository groups, AuthFacade auth) {
        this.directory = directory; this.groups = groups; this.auth = auth;
    }
    @GetMapping("/principals")
    public List<DirectoryPrincipal> principals(@RequestParam(defaultValue = "") String query,
            @RequestParam(defaultValue = "USER,GROUP") String types) {
        List<DirectoryPrincipal.Type> requested = Arrays.stream(types.split(",")).map(String::trim)
                .filter(s -> !s.isBlank()).map(String::toUpperCase).map(DirectoryPrincipal.Type::valueOf).toList();
        boolean admin = auth.current().isAdmin();
        return directory.search(query, requested, 50).stream()
                .filter(principal -> principal.type() != DirectoryPrincipal.Type.GROUP || admin
                        || groups.findById(principal.email().toLowerCase()).map(WorkspaceGroup::isVisibleToUsers).orElse(false))
                .toList();
    }
}
