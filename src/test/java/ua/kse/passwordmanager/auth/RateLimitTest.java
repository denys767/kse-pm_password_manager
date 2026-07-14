package ua.kse.passwordmanager.auth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = {
        "pm.allow-insecure-dev=true",
        "pm.rate-limit.requests-per-minute=3",
})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class RateLimitTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void throttlesAfterConfiguredLimit() throws Exception {
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(get("/api/me").header("X-Dev-User", "rate@kse.org.ua"))
                    .andExpect(status().isOk());
        }
        mockMvc.perform(get("/api/me").header("X-Dev-User", "rate@kse.org.ua"))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void healthEndpointIsNeverThrottled() throws Exception {
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(get("/api/health")).andExpect(status().isOk());
        }
    }
}
