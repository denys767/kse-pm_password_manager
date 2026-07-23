package ua.kse.passwordmanager.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Runs before MVC argument validation so the extension OAuth boundary cannot
 * be probed through validation responses.  Controllers keep their own guard
 * as a defence in depth check for non-HTTP invocations.
 */
@Component
public class PasskeyExtensionClientFilter extends OncePerRequestFilter {
    private final AuthFacade auth;

    public PasskeyExtensionClientFilter(AuthFacade auth) {
        this.auth = auth;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/passkeys");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (!auth.isExtensionClient()) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"error\":\"Passkey material is available only to the extension OAuth client and audience\"}");
            return;
        }
        filterChain.doFilter(request, response);
    }
}
