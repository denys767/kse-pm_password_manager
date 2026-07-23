package ua.kse.passwordmanager.directory;

/** Local access state. REVOKED always wins over Google and role overrides. */
public enum WorkspaceAccountStatus { ACTIVE, SUSPENDED, REVOKED }
