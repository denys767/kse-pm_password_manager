package ua.kse.passwordmanager.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import ua.kse.passwordmanager.directory.WorkspaceRoleOverride;
import ua.kse.passwordmanager.directory.WorkspaceUser;
import ua.kse.passwordmanager.directory.WorkspaceUserRepository;

/**
 * The production (non-dev) governance path. A Google Directory outage must not
 * turn into "nobody can open their vault", but it must not hand out access the
 * snapshot already contradicts either.
 */
class GovernedAuthenticationFilterTest {

    private final WorkspaceUserRepository users = mock(WorkspaceUserRepository.class);
    private final FilterChain chain = mock(FilterChain.class);
    private final MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/me");
    private final MockHttpServletResponse response = new MockHttpServletResponse();

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private GovernedAuthenticationFilter filter(boolean provisionalAccess) {
        return new GovernedAuthenticationFilter(users, new MockEnvironment(), "kse.org.ua", provisionalAccess);
    }

    private void authenticateAs(String email) {
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "none")
                .claim("email", email).claim("name", "Test User").build();
        SecurityContextHolder.getContext().setAuthentication(
                new JwtAuthenticationToken(jwt, AuthorityUtils.NO_AUTHORITIES));
    }

    @Test
    void admitsInDomainUserWhileTheSnapshotHasNeverBeenFetched() throws Exception {
        when(users.findById("someone@kse.org.ua")).thenReturn(Optional.empty());
        when(users.count()).thenReturn(0L);
        authenticateAs("someone@kse.org.ua");

        filter(true).doFilter(request, response, chain);

        verify(chain).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(200);
        var governed = (GovernedAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        // Degraded access is always an ordinary user, never an administrator.
        assertThat(governed.getPrincipal().roles()).containsExactly(WorkspaceRoleOverride.USER.name());
    }

    @Test
    void deniesOutOfDomainAccountEvenWithoutASnapshot() throws Exception {
        when(users.findById("intruder@example.com")).thenReturn(Optional.empty());
        when(users.count()).thenReturn(0L);
        authenticateAs("intruder@example.com");

        filter(true).doFilter(request, response, chain);

        verify(chain, never()).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentAsString()).contains("has not been synchronized yet");
    }

    @Test
    void deniesUnknownAccountOnceTheSnapshotExists() throws Exception {
        when(users.findById("stranger@kse.org.ua")).thenReturn(Optional.empty());
        when(users.count()).thenReturn(42L);
        authenticateAs("stranger@kse.org.ua");

        filter(true).doFilter(request, response, chain);

        verify(chain, never()).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentAsString()).contains("not provisioned");
    }

    @Test
    void failsClosedWhenProvisionalAccessIsDisabled() throws Exception {
        when(users.findById("someone@kse.org.ua")).thenReturn(Optional.empty());
        when(users.count()).thenReturn(0L);
        authenticateAs("someone@kse.org.ua");

        filter(false).doFilter(request, response, chain);

        verify(chain, never()).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void knownAccountKeepsItsGovernedRole() throws Exception {
        WorkspaceUser admin = new WorkspaceUser("boss@kse.org.ua");
        admin.setRoleOverride(WorkspaceRoleOverride.ADMIN);
        when(users.findById("boss@kse.org.ua")).thenReturn(Optional.of(admin));
        authenticateAs("boss@kse.org.ua");

        filter(true).doFilter(request, response, chain);

        verify(chain).doFilter(any(), any());
        var governed = (GovernedAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        assertThat(governed.getPrincipal().roles()).containsExactly(WorkspaceRoleOverride.ADMIN.name());
    }

    @Test
    void suspendedAccountIsStillRefused() throws Exception {
        WorkspaceUser suspended = new WorkspaceUser("gone@kse.org.ua");
        suspended.setStatus(ua.kse.passwordmanager.directory.WorkspaceAccountStatus.SUSPENDED);
        when(users.findById("gone@kse.org.ua")).thenReturn(Optional.of(suspended));
        authenticateAs("gone@kse.org.ua");

        filter(true).doFilter(request, response, chain);

        verify(chain, never()).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentAsString()).contains("suspended");
    }
}
