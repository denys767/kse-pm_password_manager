package ua.kse.passwordmanager.audit;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import ua.kse.passwordmanager.common.BadRequestException;
import ua.kse.passwordmanager.common.ForbiddenException;

/**
 * Internal ingestion endpoint for a Keycloak EventListener provider. It is
 * deliberately unauthenticated at the HTTP layer because Keycloak sends no
 * application JWT; callers instead need the internal shared secret header.
 */
@RestController
@RequestMapping("/api/audit/keycloak-events")
public class KeycloakEventController {

    public static final String SECRET_HEADER = "X-Keycloak-Events-Secret";

    private final AuditService auditService;
    private final String sharedSecret;

    public KeycloakEventController(AuditService auditService,
                                   @Value("${pm.audit.keycloak-events-secret:}") String sharedSecret) {
        this.auditService = auditService;
        this.sharedSecret = sharedSecret;
    }

    @PostMapping
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void ingest(@RequestHeader(value = SECRET_HEADER, required = false) String providedSecret,
                       @Valid @RequestBody KeycloakEventRequest request) {
        if (!validSecret(providedSecret)) {
            throw new ForbiddenException("Invalid Keycloak event secret");
        }
        AuditAction action = switch (request.type().trim().toUpperCase(Locale.ROOT)) {
            case "LOGIN" -> AuditAction.LOGIN;
            case "LOGIN_ERROR" -> AuditAction.LOGIN_FAILED;
            case "LOGOUT" -> AuditAction.LOGOUT;
            default -> throw new BadRequestException("Unsupported Keycloak event type: " + request.type());
        };
        auditService.record(request.email().trim().toLowerCase(Locale.ROOT), action, null, null,
                null, request.details());
    }

    private boolean validSecret(String providedSecret) {
        if (sharedSecret == null || sharedSecret.isBlank() || providedSecret == null) {
            return false;
        }
        return MessageDigest.isEqual(sharedSecret.getBytes(StandardCharsets.UTF_8),
                providedSecret.getBytes(StandardCharsets.UTF_8));
    }

    public record KeycloakEventRequest(
            @NotBlank @Size(max = 64) String type,
            @NotBlank @Size(max = 255) String email,
            @Size(max = 1024) String details) { }
}
