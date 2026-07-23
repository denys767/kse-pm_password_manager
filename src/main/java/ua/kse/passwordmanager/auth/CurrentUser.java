package ua.kse.passwordmanager.auth;

import java.util.Set;

public record CurrentUser(String email, String displayName, Set<String> roles, Set<String> groups) {

    public boolean canReadAudit() {
        return roles.contains("ADMIN") || roles.contains("SECURITY");
    }

    public boolean isAdmin() {
        return roles.contains("ADMIN");
    }
}
