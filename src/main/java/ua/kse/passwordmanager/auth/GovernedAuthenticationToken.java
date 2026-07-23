package ua.kse.passwordmanager.auth;

import java.util.Collection;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Authentication after the Workspace governance decision has been applied.
 * Keycloak is deliberately retained only as an identity/token issuer; its
 * realm roles never become application authorities.
 */
public final class GovernedAuthenticationToken extends AbstractAuthenticationToken {
    private final CurrentUser principal;
    private final Jwt jwt;

    public GovernedAuthenticationToken(CurrentUser principal, Jwt jwt,
                                      Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.jwt = jwt;
        setAuthenticated(true);
    }

    @Override public Object getCredentials() { return jwt; }
    @Override public CurrentUser getPrincipal() { return principal; }
    public Jwt getJwt() { return jwt; }
}
