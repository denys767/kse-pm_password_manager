package ua.kse.passwordmanager.auth;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class DevProfileGuardTest {

    @Test
    void failsStartupWithoutExplicitAcknowledgement() {
        var guard = new DevProfileGuard(new MockEnvironment());
        assertThrows(IllegalStateException.class, guard::afterPropertiesSet);
    }

    @Test
    void passesWhenAcknowledged() {
        var environment = new MockEnvironment().withProperty(DevProfileGuard.PROPERTY, "true");
        var guard = new DevProfileGuard(environment);
        assertDoesNotThrow(guard::afterPropertiesSet);
    }
}
