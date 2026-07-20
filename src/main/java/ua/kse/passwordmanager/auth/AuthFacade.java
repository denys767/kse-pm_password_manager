package ua.kse.passwordmanager.auth;

import java.util.List;
import java.util.Set;
import java.time.Instant;
import java.util.stream.Collectors;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

@Component
public class AuthFacade {

    public CurrentUser current() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            throw new IllegalStateException("No authenticated user in security context");
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
            Set<String> roles = rolesFrom(jwtAuth.getAuthorities());
            List<String> groupsClaim = jwt.getClaimAsStringList("groups");
            Set<String> groups = groupsClaim == null
                    ? Set.of()
                    : groupsClaim.stream()
                            .map(g -> g.startsWith("/") ? g.substring(1) : g)
                            .map(String::toLowerCase)
                            .collect(Collectors.toUnmodifiableSet());
            return new CurrentUser(email.toLowerCase(), name, roles, groups);
        }
        throw new IllegalStateException("Unsupported authentication type: " + auth.getClass());
    }

    /** Destructive vault recovery requires a recent interactive SSO login. */
    public boolean hasRecentAuthentication() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof CurrentUser) {
            return true; // Explicitly insecure development profile.
        }
        if (auth instanceof JwtAuthenticationToken jwtAuth) {
            Object authTime = jwtAuth.getToken().getClaim("auth_time");
            if (authTime instanceof Number seconds) {
                return Instant.now().minusSeconds(300).isBefore(Instant.ofEpochSecond(seconds.longValue()));
            }
        }
        return false;
    }

    private static Set<String> rolesFrom(Iterable<? extends GrantedAuthority> authorities) {
        Set<String> roles = new java.util.HashSet<>();
        for (GrantedAuthority a : authorities) {
            String value = a.getAuthority();
            if (value.startsWith("ROLE_")) {
                roles.add(value.substring("ROLE_".length()).toUpperCase());
            }
        }
        return Set.copyOf(roles);
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
