package ua.kse.passwordmanager.audit;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private static final int MAX_SIZE = 200;

    private final AuditService auditService;
    private final AuditAnomalyService anomalyService;

    public AuditController(AuditService auditService, AuditAnomalyService anomalyService) {
        this.auditService = auditService;
        this.anomalyService = anomalyService;
    }

    /** Paged, filterable audit log. All filters are optional and combine with AND. */
    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY')")
    public AuditPageDto search(@RequestParam(defaultValue = "0") int page,
                                @RequestParam(defaultValue = "50") int size,
                                @RequestParam(required = false) Instant from,
                                @RequestParam(required = false) Instant to,
                                @RequestParam(required = false) String actorEmail,
                                @RequestParam(required = false) AuditAction action,
                                @RequestParam(required = false) UUID itemId) {
        return auditService.search(Math.max(page, 0), Math.clamp(size, 1, MAX_SIZE), from, to, actorEmail, action, itemId);
    }

    /** Threshold-based anomalies (mass copy/share/revoke) over recent activity. */
    @GetMapping("/anomalies")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY')")
    public List<AnomalyDto> anomalies() {
        return anomalyService.detect();
    }
}
