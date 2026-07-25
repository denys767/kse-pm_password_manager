package ua.kse.passwordmanager.audit;

import java.util.List;

/** Paged audit log response; {@code totalElements} lets the UI render page controls. */
public record AuditPageDto(List<AuditEvent> content, int page, int size, long totalElements, int totalPages) {
}
