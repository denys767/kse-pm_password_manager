package ua.kse.passwordmanager.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;

/**
 * Production security: the app is an OAuth2 resource server, tokens are issued
 * by Keycloak (which brokers Google Workspace SSO). Authorities are resolved
 * exclusively from the local Workspace governance snapshot after token
 * authentication; realm roles are intentionally ignored.
 */
@Configuration
@EnableWebSecurity
@Profile("!dev")
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, GovernedAuthenticationFilter governedAuthenticationFilter,
                                           PasskeyExtensionClientFilter passkeyExtensionClientFilter) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/health", "/api/config", "/api/audit/keycloak-events", "/api/external-shares/**", "/actuator/health").permitAll()
                        // API documentation and the remaining actuator endpoints are
                        // denied here as well as in nginx. Relying on the proxy alone
                        // put them one misconfiguration — a second ingress, a direct
                        // container port, a port-forward — away from being public.
                        .requestMatchers("/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**", "/actuator/**").denyAll()
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().permitAll())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt())
                .addFilterAfter(governedAuthenticationFilter, BearerTokenAuthenticationFilter.class)
                .addFilterAfter(passkeyExtensionClientFilter, GovernedAuthenticationFilter.class);
        return http.build();
    }
}
