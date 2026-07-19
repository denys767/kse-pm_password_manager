package ua.kse.passwordmanager.audit;

import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/audit")
public class AuditController {

    private static final int MAX_LIMIT = 500;

    private final AuditService auditService;
    private final AuditAnomalyService anomalyService;

    public AuditController(AuditService auditService, AuditAnomalyService anomalyService) {
        this.auditService = auditService;
        this.anomalyService = anomalyService;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY')")
    public List<AuditEvent> latest(@RequestParam(defaultValue = "100") int limit) {
        return auditService.latest(Math.clamp(limit, 1, MAX_LIMIT));
    }

    /** Threshold-based anomalies (mass copy/share/revoke) over recent activity. */
    @GetMapping("/anomalies")
    @PreAuthorize("hasAnyRole('ADMIN', 'SECURITY')")
    public List<AnomalyDto> anomalies() {
        return anomalyService.detect();
    }
}
