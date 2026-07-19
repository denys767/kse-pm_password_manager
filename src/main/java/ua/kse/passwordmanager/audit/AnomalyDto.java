package ua.kse.passwordmanager.audit;

public record AnomalyDto(
        String actorEmail,
        AuditAction action,
        long count,
        int windowMinutes,
        long threshold) {
}
