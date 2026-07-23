package ua.kse.passwordmanager.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Dev-only security: identity is taken from X-Dev-User / X-Dev-Roles /
 * X-Dev-Groups headers so the app can run without Keycloak. Insecure by
 * design — never enable the "dev" profile outside local development.
 */
@Configuration
@EnableWebSecurity
@Profile("dev")
public class DevSecurityConfig {

    public static final String USER_HEADER = "X-Dev-User";
    public static final String ROLES_HEADER = "X-Dev-Roles";
    public static final String GROUPS_HEADER = "X-Dev-Groups";
    public static final String OAUTH_CLIENT_HEADER = "X-Dev-OAuth-Client";
    public static final String OAUTH_AUDIENCE_HEADER = "X-Dev-OAuth-Audience";

    @Bean
    public SecurityFilterChain devFilterChain(HttpSecurity http, GovernedAuthenticationFilter governedAuthenticationFilter,
                                              PasskeyExtensionClientFilter passkeyExtensionClientFilter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/health", "/api/config", "/api/audit/keycloak-events", "/api/external-shares/**", "/actuator/health").permitAll()
                .requestMatchers("/api/**").authenticated()
                .anyRequest().permitAll())
                .addFilterBefore(new DevUserFilter(), AnonymousAuthenticationFilter.class)
                .addFilterAfter(governedAuthenticationFilter, DevUserFilter.class)
                .addFilterAfter(passkeyExtensionClientFilter, GovernedAuthenticationFilter.class);
        return http.build();
    }

    static class DevUserFilter extends OncePerRequestFilter {

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                        FilterChain filterChain) throws ServletException, IOException {
            String email = request.getHeader(USER_HEADER);
            if (email != null && !email.isBlank()) {
                Set<String> roles = splitHeader(request.getHeader(ROLES_HEADER), "user").stream()
                        .map(r -> r.toUpperCase(Locale.ROOT))
                        .collect(Collectors.toUnmodifiableSet());
                Set<String> groups = Set.copyOf(splitHeader(request.getHeader(GROUPS_HEADER), null));
                CurrentUser user = new CurrentUser(email.toLowerCase(Locale.ROOT), email, roles, groups);
                // Header roles are a development-only identity seed. A provisioned
                // Workspace user is replaced by GovernedAuthenticationFilter.
                List<GrantedAuthority> authorities = roles.stream()
                        .<GrantedAuthority>map(role -> new SimpleGrantedAuthority("ROLE_" + role)).toList();
                var authentication = new UsernamePasswordAuthenticationToken(user, null, authorities);
                boolean extensionClient = "kse-pm-extension".equals(request.getHeader(OAUTH_CLIENT_HEADER))
                        && request.getHeader(OAUTH_AUDIENCE_HEADER) != null
                        && Arrays.asList(request.getHeader(OAUTH_AUDIENCE_HEADER).split(","))
                                .stream().map(String::trim).anyMatch("kse-pm-extension"::equals);
                authentication.setDetails(new AuthFacade.ClientAccess(extensionClient));
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
            filterChain.doFilter(request, response);
        }

        private static List<String> splitHeader(String value, String fallback) {
            if (value == null || value.isBlank()) {
                return fallback == null ? List.of() : List.of(fallback);
            }
            return Arrays.stream(value.split(","))
                    .map(String::trim)
                    .filter(s -> !s.isEmpty())
                    .map(s -> s.toLowerCase(Locale.ROOT))
                    .toList();
        }
    }
}
