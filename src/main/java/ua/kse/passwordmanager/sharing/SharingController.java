package ua.kse.passwordmanager.sharing;

import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import ua.kse.passwordmanager.auth.AuthFacade;

@RestController
@RequestMapping("/api/vault/items/{itemId}/permissions")
public class SharingController {

    private final SharingService sharingService;
    private final AuthFacade authFacade;

    public SharingController(SharingService sharingService, AuthFacade authFacade) {
        this.sharingService = sharingService;
        this.authFacade = authFacade;
    }

    @GetMapping
    public List<PermissionResponse> list(@PathVariable UUID itemId) {
        return sharingService.listPermissions(authFacade.current(), itemId);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public PermissionResponse share(@PathVariable UUID itemId,
                                    @Valid @RequestBody ShareRequest request) {
        return sharingService.share(authFacade.current(), itemId, request);
    }

    @GetMapping("/{permissionId}/members")
    public List<PermissionMemberResponse> members(@PathVariable UUID itemId, @PathVariable UUID permissionId) {
        return sharingService.listMembers(authFacade.current(), itemId, permissionId);
    }

    @PostMapping("/{permissionId}/provision")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void provision(@PathVariable UUID itemId, @PathVariable UUID permissionId,
                          @Valid @RequestBody ProvisionPermissionMembersRequest request) {
        sharingService.provisionMembers(authFacade.current(), itemId, permissionId, request);
    }

    @PostMapping("/{permissionId}/sync")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void sync(@PathVariable UUID itemId, @PathVariable UUID permissionId) {
        sharingService.syncGroup(authFacade.current(), itemId, permissionId);
    }

    @PatchMapping("/{permissionId}")
    public PermissionResponse updateRole(@PathVariable UUID itemId, @PathVariable UUID permissionId,
                                         @Valid @RequestBody UpdatePermissionRoleRequest request) {
        return sharingService.updateRole(authFacade.current(), itemId, permissionId, request);
    }

    @DeleteMapping("/{permissionId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revoke(@PathVariable UUID itemId, @PathVariable UUID permissionId) {
        sharingService.revoke(authFacade.current(), itemId, permissionId);
    }
}
