package ua.kse.passwordmanager.externalsharing;

import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.http.HttpStatus;
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
public class ExternalShareController {
    private final ExternalShareService service;
    private final AuthFacade auth;

    public ExternalShareController(ExternalShareService service, AuthFacade auth) {
        this.service = service;
        this.auth = auth;
    }

    @PostMapping("/api/vault/items/{itemId}/external-shares")
    @ResponseStatus(HttpStatus.CREATED)
    public ExternalShareDtos.CreatedResponse create(@PathVariable UUID itemId,
            @Valid @RequestBody ExternalShareDtos.CreateRequest request) {
        return service.create(auth.current(), itemId, request);
    }

    @DeleteMapping("/api/vault/items/{itemId}/external-shares/{shareId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void revoke(@PathVariable UUID itemId, @PathVariable UUID shareId) {
        service.revoke(auth.current(), itemId, shareId);
    }

    /** Extend the existing encrypted package without rotating its id or URL. */
    @PostMapping("/api/vault/items/{itemId}/external-shares/{shareId}/extend-24-hours")
    public ExternalShareDtos.CreatedResponse extend24Hours(@PathVariable UUID itemId,
            @PathVariable UUID shareId) {
        return service.extend24Hours(auth.current(), itemId, shareId);
    }

    @GetMapping("/api/external-shares/{shareId}")
    public ExternalShareDtos.PublicPackageResponse read(@PathVariable UUID shareId) {
        return service.read(shareId);
    }
}
