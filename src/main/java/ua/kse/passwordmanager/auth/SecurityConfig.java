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
                        // Swagger UI and non-API actuator endpoints fall through to
                        // anyRequest().permitAll(); the reverse proxy blocks /actuator/*
                        // (except health) from the outside.
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().permitAll())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt())
                .addFilterAfter(governedAuthenticationFilter, BearerTokenAuthenticationFilter.class)
                .addFilterAfter(passkeyExtensionClientFilter, GovernedAuthenticationFilter.class);
        return http.build();
    }
}
