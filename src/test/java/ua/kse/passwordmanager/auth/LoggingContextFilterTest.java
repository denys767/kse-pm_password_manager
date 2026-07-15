package ua.kse.passwordmanager.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Verifies LoggingContextFilter actually enriches log events with actorEmail
 * and requestId during a real authenticated request, and that MDC does not
 * leak once the request completes.
 */
@SpringBootTest(properties = "pm.allow-insecure-dev=true")
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class LoggingContextFilterTest {

    @Autowired
    private MockMvc mockMvc;

    private ListAppender<ILoggingEvent> appender;
    private Logger filterLogger;
    private Level originalLevel;

    @BeforeEach
    void attachAppender() {
        filterLogger = (Logger) LoggerFactory.getLogger(LoggingContextFilter.class);
        originalLevel = filterLogger.getLevel();
        filterLogger.setLevel(Level.DEBUG);
        appender = new ListAppender<>();
        appender.start();
        filterLogger.addAppender(appender);
    }

    @AfterEach
    void detachAppender() {
        filterLogger.detachAppender(appender);
        filterLogger.setLevel(originalLevel);
    }

    @Test
    void enrichesLogEventsWithActorAndRequestIdThenClearsMdc() throws Exception {
        String email = "logging-mdc@kse.org.ua";
        mockMvc.perform(get("/api/me").header("X-Dev-User", email))
                .andExpect(status().isOk());

        List<ILoggingEvent> capturedDuringRequest = appender.list.stream()
                .filter(event -> email.equals(event.getMDCPropertyMap().get(LoggingContextFilter.ACTOR_EMAIL_KEY)))
                .toList();
        assertFalse(capturedDuringRequest.isEmpty(),
                "expected at least one log event carrying the actorEmail MDC value");

        String requestId = capturedDuringRequest.get(0).getMDCPropertyMap()
                .get(LoggingContextFilter.REQUEST_ID_KEY);
        assertTrue(requestId != null && !requestId.isBlank());
        assertDoesNotThrowOnParse(requestId);

        // Every captured event from this request must share the same requestId.
        for (ILoggingEvent event : capturedDuringRequest) {
            assertEquals(requestId, event.getMDCPropertyMap().get(LoggingContextFilter.REQUEST_ID_KEY));
        }

        // MDC must not leak into the test thread after the request completes.
        assertNull(MDC.get(LoggingContextFilter.ACTOR_EMAIL_KEY));
        assertNull(MDC.get(LoggingContextFilter.REQUEST_ID_KEY));
    }

    private static void assertDoesNotThrowOnParse(String requestId) {
        UUID.fromString(requestId);
    }
}
