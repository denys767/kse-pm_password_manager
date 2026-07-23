package ua.kse.passwordmanager.vault;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.util.List;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;
import ua.kse.passwordmanager.auth.AuthFacade;
import ua.kse.passwordmanager.common.ForbiddenException;

/** Central tag catalogue and maintenance for local Workspace administrators. */
@RestController
@RequestMapping("/api/admin/tags")
public class AdminTagController {
    private final AuthFacade auth;
    private final AdminTagService tags;

    public AdminTagController(AuthFacade auth, AdminTagService tags) {
        this.auth = auth;
        this.tags = tags;
    }

    @GetMapping
    public List<AdminTagService.TagSummary> list() {
        requireAdmin();
        return tags.list();
    }

    @PatchMapping("/{tag}")
    public AdminTagService.TagSummary rename(@PathVariable String tag,
                                              @Valid @RequestBody RenameRequest request) {
        requireAdmin();
        return tags.rename(auth.current(), tag, request.newName());
    }

    @DeleteMapping("/{tag}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable String tag) {
        requireAdmin();
        tags.delete(auth.current(), tag);
    }

    private void requireAdmin() {
        if (!auth.current().isAdmin()) throw new ForbiddenException("Administrator role required");
    }

    public record RenameRequest(@NotBlank String newName) { }
}
