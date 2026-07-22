package ua.kse.passwordmanager.directory;

import java.util.Arrays;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/directory")
public class DirectoryController {
    private final WorkspaceDirectoryClient directory;
    public DirectoryController(WorkspaceDirectoryClient directory) { this.directory = directory; }
    @GetMapping("/principals")
    public List<DirectoryPrincipal> principals(@RequestParam(defaultValue = "") String query,
            @RequestParam(defaultValue = "USER,GROUP") String types) {
        List<DirectoryPrincipal.Type> requested = Arrays.stream(types.split(",")).map(String::trim)
                .filter(s -> !s.isBlank()).map(String::toUpperCase).map(DirectoryPrincipal.Type::valueOf).toList();
        return directory.search(query, requested, 50);
    }
}
