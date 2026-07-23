package ua.kse.passwordmanager.recovery;

import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.web.bind.annotation.*;
import ua.kse.passwordmanager.auth.AuthFacade;
import ua.kse.passwordmanager.common.ForbiddenException;

/** User-facing escrow endpoints. The public key is safe to cache; envelope
 * writes remain restricted to the owner of the protected resource. */
@RestController
@RequestMapping("/api/recovery")
public class RecoveryController {
    private final RecoveryService recovery; private final AuthFacade auth; private final UserNotificationRepository notifications;
    public RecoveryController(RecoveryService recovery, AuthFacade auth, UserNotificationRepository notifications) { this.recovery = recovery; this.auth = auth; this.notifications = notifications; }
    @GetMapping("/public-key") public RecoveryDtos.PublicKeyResponse publicKey() { return recovery.publicKey(); }
    @GetMapping("/coverage/me") public RecoveryDtos.CoverageResponse coverage() { return recovery.coverageFor(auth.current().email()); }
    @PutMapping("/envelopes") public void envelope(@Valid @RequestBody RecoveryDtos.EnvelopeRequest request) { recovery.putEnvelope(auth.current().email(), request); }
    @GetMapping("/notifications") public List<NotificationResponse> notifications() {
        return notifications.findByRecipientEmailOrderByCreatedAtDesc(auth.current().email()).stream().map(NotificationResponse::from).toList();
    }
    public record NotificationResponse(UUID id, String type, String message, java.time.Instant createdAt) {
        static NotificationResponse from(UserNotification n) { return new NotificationResponse(n.getId(), n.getNotificationType(), n.getMessage(), n.getCreatedAt()); }
    }
}
