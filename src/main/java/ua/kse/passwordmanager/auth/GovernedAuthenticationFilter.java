package ua.kse.passwordmanager.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ua.kse.passwordmanager.directory.WorkspaceRoleOverride;
import ua.kse.passwordmanager.directory.WorkspaceUser;
import ua.kse.passwordmanager.directory.WorkspaceUserRepository;

/** Resolves every authenticated API request through the local Workspace
 * snapshot, replacing raw Keycloak/dev roles with governed authorities. */
@Component
public class GovernedAuthenticationFilter extends OncePerRequestFilter {
    private static final org.slf4j.Logger log =
            org.slf4j.LoggerFactory.getLogger(GovernedAuthenticationFilter.class);
    /** One line per minute is enough to see the deployment is degraded without
     * turning every request into a log entry. */
    private static final long DEGRADED_LOG_INTERVAL_MS = 60_000;

    private final WorkspaceUserRepository users;
    private final boolean development;
    private final String domain;
    private final boolean provisionalAccessWhenUnsynced;
    private final java.util.concurrent.atomic.AtomicLong lastDegradedLogAt =
            new java.util.concurrent.atomic.AtomicLong();

    public GovernedAuthenticationFilter(WorkspaceUserRepository users, Environment environment,
            @Value("${pm.google-workspace.domain:}") String domain,
            @Value("${pm.google-workspace.provisional-access-when-unsynced:false}") boolean provisionalAccessWhenUnsynced) {
        this.users = users;
        this.development = List.of(environment.getActiveProfiles()).contains("dev");
        this.domain = domain == null ? "" : domain.trim().toLowerCase(Locale.ROOT);
        this.provisionalAccessWhenUnsynced = provisionalAccessWhenUnsynced;
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
            if (development) {
                // Development tests intentionally remain usable without a
                // Directory fixture. Production is governed below.
                chain.doFilter(request, response);
                return;
            }
            if (!degradedAccessAllowed(identity.email())) {
                deny(response, users.count() == 0
                        // A snapshot that was never fetched is an operational
                        // failure, not a decision about this account. Saying
                        // "not provisioned" sent operators looking at the wrong
                        // thing entirely.
                        ? "Google Workspace directory has not been synchronized yet; try again shortly"
                        : "Workspace account is not provisioned");
                return;
            }
            grant(request, response, chain, authentication, identity, WorkspaceRoleOverride.USER);
            return;
        }
        if (!local.hasEffectiveAccess()) {
            deny(response, "Account access has been suspended, revoked, or removed from Workspace");
            return;
        }
        grant(request, response, chain, authentication, identity, local.effectiveRole());
    }

    /**
     * Degraded mode, off by default: the local Workspace snapshot is empty, so
     * the directory has never been read (fresh database, expired caller
     * credentials, Google outage) and every single request would otherwise be
     * denied. With
     * pm.google-workspace.provisional-access-when-unsynced=true an in-domain
     * account that already passed SSO is admitted as an ordinary user — never
     * as an administrator, and never once the snapshot exists.
     *
     * <p>It defaults to false because an empty table is not only the cold-start
     * state: a sync that failed partway through leaves the same condition, and
     * in that window a revoked or never-provisioned in-domain account would be
     * let in. Availability over governance has to be an explicit choice.
     */
    private boolean degradedAccessAllowed(String email) {
        if (!provisionalAccessWhenUnsynced || domain.isEmpty()) return false;
        if (!email.endsWith("@" + domain)) return false;
        if (users.count() > 0) return false;
        long now = System.currentTimeMillis();
        long last = lastDegradedLogAt.get();
        if (now - last > DEGRADED_LOG_INTERVAL_MS && lastDegradedLogAt.compareAndSet(last, now)) {
            log.warn("Google Workspace snapshot is empty; admitting in-domain accounts as USER until the "
                    + "directory sync succeeds. Roles and revocations are NOT enforced in this state.");
        }
        return true;
    }

    private void grant(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
                       Authentication authentication, Identity identity, WorkspaceRoleOverride role)
            throws ServletException, IOException {
        CurrentUser governed = new CurrentUser(identity.email(), identity.displayName(),
                Set.of(role.name()), Set.of());
        var replacement = new GovernedAuthenticationToken(governed, identity.jwt(),
                List.of(new SimpleGrantedAuthority("ROLE_" + role.name())));
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
