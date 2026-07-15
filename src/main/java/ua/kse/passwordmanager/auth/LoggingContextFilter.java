package ua.kse.passwordmanager.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Enriches every log line for a request with actorEmail and requestId, so
 * technical logs (JSON/ECS in non-dev profiles) can be correlated with a
 * specific request and user — complementing, not replacing, the business
 * audit_events log. No explicit @Order: runs after Spring Security's filter
 * chain, so the SecurityContext is already populated when this executes.
 */
@Component
public class LoggingContextFilter extends OncePerRequestFilter {

    static final String ACTOR_EMAIL_KEY = "actorEmail";
    static final String REQUEST_ID_KEY = "requestId";

    private static final Logger log = LoggerFactory.getLogger(LoggingContextFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        MDC.put(REQUEST_ID_KEY, UUID.randomUUID().toString());
        currentActorEmail().ifPresent(email -> MDC.put(ACTOR_EMAIL_KEY, email));
        try {
            filterChain.doFilter(request, response);
            log.debug("{} {} -> {}", request.getMethod(), request.getRequestURI(), response.getStatus());
        } finally {
            MDC.remove(ACTOR_EMAIL_KEY);
            MDC.remove(REQUEST_ID_KEY);
        }
    }

    private static Optional<String> currentActorEmail() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return Optional.empty();
        }
        if (auth.getPrincipal() instanceof CurrentUser user) {
            return Optional.of(user.email());
        }
        // JwtAuthenticationToken (prod): getName() resolves to the JWT subject,
        // a reasonable correlation id even without re-deriving the email claim.
        return auth.getName() != null && !auth.getName().isBlank()
                ? Optional.of(auth.getName())
                : Optional.empty();
    }
}
