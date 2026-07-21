package ua.kse.passwordmanager.keycloak;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;
import ua.kse.passwordmanager.common.BadGatewayException;

class KeycloakAdminClientTest {

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) server.stop(0);
    }

    @Test
    void obtainsServiceTokenThenFindsGroupAndItsMembers() throws Exception {
        AtomicInteger tokenCalls = new AtomicInteger();
        server = server(exchange -> {
            if (exchange.getRequestURI().getPath().endsWith("/token")) {
                tokenCalls.incrementAndGet();
                assertThat(exchange.getRequestMethod()).isEqualTo("POST");
                assertThat(exchange.getRequestHeaders().getFirst("Content-Type"))
                        .startsWith("application/x-www-form-urlencoded");
                respond(exchange, 200, "{\"access_token\":\"service-token\"}");
            } else if (exchange.getRequestURI().getPath().endsWith("/groups")) {
                assertThat(exchange.getRequestURI().getQuery()).isEqualTo("search=dev-team");
                assertThat(exchange.getRequestHeaders().getFirst("Authorization")).isEqualTo("Bearer service-token");
                respond(exchange, 200, "[{\"id\":\"group-1\",\"name\":\"dev-team\"}]");
            } else if (exchange.getRequestURI().getPath().endsWith("/groups/group-1/members")) {
                respond(exchange, 200, "[{\"email\":\"alice@kse.org.ua\"},{\"email\":\"bob@kse.org.ua\"}]");
            } else {
                respond(exchange, 404, "{}");
            }
        });

        assertThat(client().membersOfGroup("dev-team"))
                .containsExactly("alice@kse.org.ua", "bob@kse.org.ua");
        assertThat(tokenCalls).hasValue(1);
    }

    @Test
    void reportsTokenUnauthorized() throws Exception {
        server = server(exchange -> respond(exchange, 401, "unauthorized"));
        assertThatThrownBy(() -> client().membersOfGroup("dev-team"))
                .isInstanceOf(BadGatewayException.class)
                .hasMessage("Keycloak admin token request failed");
    }

    @Test
    void listsOnlyNonBlankGroupNames() throws Exception {
        server = server(exchange -> {
            if (exchange.getRequestURI().getPath().endsWith("/token")) {
                respond(exchange, 200, "{\"access_token\":\"service-token\"}");
            } else if (exchange.getRequestURI().getPath().endsWith("/groups")) {
                assertThat(exchange.getRequestURI().getQuery()).isNull();
                respond(exchange, 200, "[{\"id\":\"a\",\"name\":\"z-team\"},{\"id\":\"b\",\"name\":\"\"},{\"id\":\"c\",\"name\":\"a-team\"}]");
            } else {
                respond(exchange, 404, "{}");
            }
        });
        assertThat(client().groups()).containsExactly("a-team", "z-team");
    }

    @Test
    void handlesGroupNotFoundAndEmptyGroup() throws Exception {
        server = server(exchange -> {
            if (exchange.getRequestURI().getPath().endsWith("/token")) {
                respond(exchange, 200, "{\"access_token\":\"service-token\"}");
            } else if (exchange.getRequestURI().getPath().endsWith("/groups")) {
                respond(exchange, 200, "[]");
            } else {
                respond(exchange, 404, "{}");
            }
        });
        assertThat(client().membersOfGroup("missing")).isEmpty();

        server.stop(0);
        server = server(exchange -> {
            if (exchange.getRequestURI().getPath().endsWith("/token")) {
                respond(exchange, 200, "{\"access_token\":\"service-token\"}");
            } else if (exchange.getRequestURI().getPath().endsWith("/groups")) {
                respond(exchange, 200, "[{\"id\":\"empty\",\"name\":\"dev-team\"}]");
            } else if (exchange.getRequestURI().getPath().endsWith("/groups/empty/members")) {
                respond(exchange, 200, "[]");
            } else {
                respond(exchange, 404, "{}");
            }
        });
        assertThat(client().membersOfGroup("dev-team")).isEmpty();
    }

    private KeycloakAdminClient client() {
        return new KeycloakAdminClient(RestClient.builder().build(),
                "http://127.0.0.1:" + server.getAddress().getPort() + "/realms/kse-pm", "secret");
    }

    private static HttpServer server(Handler handler) throws IOException {
        HttpServer httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        httpServer.createContext("/", handler::handle);
        httpServer.start();
        return httpServer;
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    @FunctionalInterface
    private interface Handler {
        void handle(HttpExchange exchange) throws IOException;
    }
}
