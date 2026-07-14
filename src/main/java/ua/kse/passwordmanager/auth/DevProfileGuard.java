package ua.kse.passwordmanager.auth;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * The dev profile trusts X-Dev-* headers blindly, so accidentally enabling it
 * outside local development would be a full authentication bypass. This guard
 * fails startup unless the operator explicitly acknowledges the risk with
 * PM_ALLOW_INSECURE_DEV=true (env var or pm.allow-insecure-dev property).
 */
@Component
@Profile("dev")
public class DevProfileGuard implements InitializingBean {

    static final String PROPERTY = "pm.allow-insecure-dev";

    private final Environment environment;

    public DevProfileGuard(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void afterPropertiesSet() {
        if (!"true".equalsIgnoreCase(environment.getProperty(PROPERTY))) {
            throw new IllegalStateException("""
                    The 'dev' profile disables real authentication (identity comes from \
                    X-Dev-* headers) and must never run outside local development. \
                    Set PM_ALLOW_INSECURE_DEV=true to confirm this is a local dev machine.""");
        }
    }
}
