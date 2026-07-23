package ua.kse.passwordmanager.common;

/** A clear, actionable mapping for Workspace/Drive storage quota exhaustion. */
public class QuotaExceededException extends RuntimeException {
    public QuotaExceededException(String message, Throwable cause) { super(message, cause); }
}
