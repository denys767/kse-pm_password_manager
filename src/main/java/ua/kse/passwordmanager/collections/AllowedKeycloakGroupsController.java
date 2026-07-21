package ua.kse.passwordmanager.collections;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import ua.kse.passwordmanager.auth.AuthFacade;

@RestController
public class AllowedKeycloakGroupsController {
    private final CollectionGroupService groups;
    private final AuthFacade auth;

    public AllowedKeycloakGroupsController(CollectionGroupService groups, AuthFacade auth) {
        this.groups = groups;
        this.auth = auth;
    }

    /** Groups usable by collection managers; the response is both allowlisted and currently in Keycloak. */
    @GetMapping("/api/collection-groups")
    public List<String> available() { return groups.available(); }

    @GetMapping("/api/admin/collection-groups")
    @PreAuthorize("hasRole('ADMIN')")
    public List<String> allowlist() { return groups.allowlist(); }

    /** Every group that exists in Keycloak right now, so an admin can pick a name instead of typing it blind. */
    @GetMapping("/api/admin/collection-groups/keycloak")
    @PreAuthorize("hasRole('ADMIN')")
    public List<String> keycloakGroups() { return groups.keycloakGroups(); }

    @PostMapping("/api/admin/collection-groups")
    @PreAuthorize("hasRole('ADMIN')")
    @ResponseStatus(HttpStatus.CREATED)
    public String add(@Valid @RequestBody GroupRequest request) {
        return groups.allow(auth.current(), request.groupName());
    }

    @DeleteMapping("/api/admin/collection-groups/{groupName}")
    @PreAuthorize("hasRole('ADMIN')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void remove(@PathVariable String groupName) { groups.disallow(auth.current(), groupName); }

    public record GroupRequest(@NotBlank @Size(max = 255) String groupName) { }
}
