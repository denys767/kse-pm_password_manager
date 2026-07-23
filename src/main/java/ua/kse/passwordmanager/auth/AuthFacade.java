package ua.kse.passwordmanager.auth;

import java.util.List;
import java.util.Set;
import java.time.Instant;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;

@Component
public class AuthFacade {
    private final String extensionClientId;
    public AuthFacade(@Value("${pm.extension.oauth-client-id:kse-pm-extension}") String extensionClientId) {
        this.extensionClientId = extensionClientId;
    }

    public CurrentUser current() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new IllegalStateException("No authenticated user in security context");
        }
        if (auth instanceof GovernedAuthenticationToken governed) {
            return governed.getPrincipal();
        }
        if (auth.getPrincipal() instanceof CurrentUser devUser) {
            return devUser;
        }
        if (auth instanceof JwtAuthenticationToken jwtAuth) {
            Jwt jwt = jwtAuth.getToken();
            String email = firstNonBlank(
                    jwt.getClaimAsString("email"),
                    jwt.getClaimAsString("preferred_username"),
                    jwt.getSubject());
            String name = firstNonBlank(jwt.getClaimAsString("name"), email);
            // This branch is intentionally identity-only and is only reachable
            // for endpoints excluded from governance. API method security always
            // receives GovernedAuthenticationToken.
            return new CurrentUser(email.toLowerCase(), name, Set.of(), Set.of());
        }
        throw new IllegalStateException("Unsupported authentication type: " + auth.getClass());
    }

    /** Destructive vault recovery requires a recent interactive SSO login. */
    public boolean hasRecentAuthentication() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = jwt(auth);
        if (auth != null && auth.getPrincipal() instanceof CurrentUser && jwt == null) {
            return true; // Explicitly insecure development profile.
        }
        if (jwt != null) {
            Object authTime = jwt.getClaim("auth_time");
            if (authTime instanceof Number seconds) {
                return Instant.now().minusSeconds(300).isBefore(Instant.ofEpochSecond(seconds.longValue()));
            }
        }
        return false;
    }

    /** Both azp and aud must identify the dedicated extension client.  Keycloak
     * needs an audience mapper for this client; accepting azp alone would let a
     * token minted for a different resource cross this API boundary. */
    public boolean isExtensionClient() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Jwt jwt = jwt(auth);
        if (auth != null && auth.getPrincipal() instanceof CurrentUser && jwt == null) {
            // Test/dev profile uses explicit headers because it has no JWT.
            return auth.getDetails() instanceof ClientAccess access && access.extensionClient();
        }
        if (jwt == null) return false;
        String authorizedParty = jwt.getClaimAsString("azp");
        List<String> audience = jwt.getAudience();
        return extensionClientId.equals(authorizedParty) && audience.contains(extensionClientId);
    }

    public record ClientAccess(boolean extensionClient) { }

    private static Jwt jwt(Authentication auth) {
        if (auth instanceof GovernedAuthenticationToken token) return token.getJwt();
        if (auth instanceof JwtAuthenticationToken token) return token.getToken();
        return null;
    }

    private static String firstNonBlank(String... values) {
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        throw new IllegalStateException("Token contains no usable identity claim");
    }
}
