package ua.kse.passwordmanager.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ua.kse.passwordmanager.directory.WorkspaceUser;
import ua.kse.passwordmanager.directory.WorkspaceUserRepository;

/** Resolves every authenticated API request through the local Workspace
 * snapshot, replacing raw Keycloak/dev roles with governed authorities. */
@Component
public class GovernedAuthenticationFilter extends OncePerRequestFilter {
    private final WorkspaceUserRepository users;
    private final boolean development;

    public GovernedAuthenticationFilter(WorkspaceUserRepository users, Environment environment) {
        this.users = users;
        this.development = List.of(environment.getActiveProfiles()).contains("dev");
    }

    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/")
                || request.getRequestURI().equals("/api/health")
                || request.getRequestURI().equals("/api/config")
                || request.getRequestURI().startsWith("/api/audit/keycloak-events")
                || request.getRequestURI().startsWith("/api/external-shares/");
    }

    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                               FilterChain chain) throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Identity identity = identity(authentication);
        if (identity == null) {
            chain.doFilter(request, response);
            return;
        }
        WorkspaceUser local = users.findById(identity.email()).orElse(null);
        if (local == null) {
            if (!development) {
                deny(response, "Workspace account is not provisioned");
                return;
            }
            // Development tests intentionally remain usable without a Directory
            // fixture. Production is fail-closed above.
            chain.doFilter(request, response);
            return;
        }
        if (!local.hasEffectiveAccess()) {
            deny(response, "Account access has been suspended, revoked, or removed from Workspace");
            return;
        }
        CurrentUser governed = new CurrentUser(identity.email(), identity.displayName(),
                Set.of(local.effectiveRole().name()), Set.of());
        var replacement = new GovernedAuthenticationToken(governed, identity.jwt(),
                List.of(new SimpleGrantedAuthority("ROLE_" + local.effectiveRole().name())));
        replacement.setDetails(authentication.getDetails());
        SecurityContextHolder.getContext().setAuthentication(replacement);
        chain.doFilter(request, response);
    }

    private static Identity identity(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) return null;
        if (auth instanceof GovernedAuthenticationToken token) {
            return new Identity(token.getPrincipal().email(), token.getPrincipal().displayName(), token.getJwt());
        }
        if (auth.getPrincipal() instanceof CurrentUser user) {
            return new Identity(user.email().toLowerCase(Locale.ROOT), user.displayName(), null);
        }
        if (auth instanceof JwtAuthenticationToken token) {
            Jwt jwt = token.getToken();
            String email = jwt.getClaimAsString("email");
            if (email == null || email.isBlank()) email = jwt.getClaimAsString("preferred_username");
            if (email == null || email.isBlank()) email = jwt.getSubject();
            return email == null || email.isBlank() ? null
                    : new Identity(email.toLowerCase(Locale.ROOT), jwt.getClaimAsString("name"), jwt);
        }
        return null;
    }

    private static void deny(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json");
        response.getWriter().write("{\"error\":\"" + message + "\"}");
    }

    private record Identity(String email, String displayName, Jwt jwt) { }
}
