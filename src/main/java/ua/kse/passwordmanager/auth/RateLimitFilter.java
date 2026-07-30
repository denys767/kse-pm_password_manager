package ua.kse.passwordmanager.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Fixed-window in-memory rate limit per client IP for /api/**. Deliberately
 * dependency-free for a single-node deployment; swap for a shared store
 * (bucket4j + Redis) when the app scales horizontally.
 *
 * <p>The unauthenticated endpoints get their own, much smaller bucket: they are
 * reachable without a token (see SecurityConfig) and this filter is the only
 * brute-force control in front of them.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class RateLimitFilter extends OncePerRequestFilter {

    private static final int MAX_TRACKED_CLIENTS = 10_000;

    /**
     * Paths that authenticate nobody, so a caller can retry a share id or the
     * Keycloak events secret as fast as the network allows.
     */
    private static final Map<String, String> UNAUTHENTICATED_BUCKETS = Map.of(
            "/api/external-shares/", "external-shares",
            "/api/audit/keycloak-events", "keycloak-events");

    /**
     * The public-key directory answers "does this Workspace user have a vault"
     * for any authenticated caller, and /lookup takes 200 addresses at a time.
     * Legitimate use is a handful of calls per share, so a bucket well below the
     * global limit costs nothing and bounds enumeration.
     */
    private static final String KEY_DIRECTORY_PREFIX = "/api/keys/";
    private static final String KEY_DIRECTORY_BUCKET = "key-directory";

    private final int requestsPerMinute;
    private final int unauthenticatedRequestsPerMinute;
    private final int keyDirectoryRequestsPerMinute;
    private final List<TrustedProxy> trustedProxies;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();

    public RateLimitFilter(@Value("${pm.rate-limit.requests-per-minute:300}") int requestsPerMinute,
                           @Value("${pm.rate-limit.unauthenticated-requests-per-minute:20}") int unauthenticatedRequestsPerMinute,
                           @Value("${pm.rate-limit.key-directory-requests-per-minute:60}") int keyDirectoryRequestsPerMinute,
                           @Value("${pm.rate-limit.trusted-proxies:}") String trustedProxies) {
        this.requestsPerMinute = requestsPerMinute;
        this.unauthenticatedRequestsPerMinute = unauthenticatedRequestsPerMinute;
        this.keyDirectoryRequestsPerMinute = keyDirectoryRequestsPerMinute;
        this.trustedProxies = parseTrustedProxies(trustedProxies);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return !uri.startsWith("/api/") || uri.equals("/api/health");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        long minute = System.currentTimeMillis() / 60_000;
        // Evict only what the current minute has already made meaningless. The
        // previous version cleared the whole map, so flooding it with distinct
        // keys reset every other client's counter as a side effect.
        if (windows.size() > MAX_TRACKED_CLIENTS) {
            windows.values().removeIf(existing -> existing.minute != minute);
        }
        String client = clientKey(request);
        String uri = request.getRequestURI();
        String bucket = unauthenticatedBucket(uri);
        int limit = unauthenticatedRequestsPerMinute;
        if (bucket == null && uri.startsWith(KEY_DIRECTORY_PREFIX)) {
            bucket = KEY_DIRECTORY_BUCKET;
            limit = keyDirectoryRequestsPerMinute;
        }
        if (bucket == null) {
            limit = requestsPerMinute;
        }
        String key = bucket == null ? client : bucket + '|' + client;
        Window window = windows.compute(key, (ignored, existing) ->
                existing == null || existing.minute != minute ? new Window(minute) : existing);
        if (window.count.incrementAndGet() > limit) {
            response.setStatus(429);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Too many requests, slow down\"}");
            return;
        }
        filterChain.doFilter(request, response);
    }

    private static String unauthenticatedBucket(String uri) {
        for (Map.Entry<String, String> entry : UNAUTHENTICATED_BUCKETS.entrySet()) {
            if (uri.startsWith(entry.getKey())) return entry.getValue();
        }
        return null;
    }

    /**
     * X-Forwarded-For is client-controlled unless the request actually came from
     * a proxy we put there, and the leftmost entry is the one the client writes.
     * So the header is read only from a trusted peer, and then right-to-left:
     * the first address that is not itself a trusted hop is the real caller.
     */
    private String clientKey(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (!isTrustedProxy(remoteAddr)) {
            return remoteAddr;
        }
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded == null || forwarded.isBlank()) {
            return remoteAddr;
        }
        String[] hops = forwarded.split(",");
        for (int i = hops.length - 1; i >= 0; i--) {
            String hop = hops[i].trim();
            if (!hop.isEmpty() && !isTrustedProxy(hop)) return hop;
        }
        // Every hop is one of ours: the nearest one is as specific as we can be.
        return remoteAddr;
    }

    private boolean isTrustedProxy(String address) {
        byte[] candidate = addressBytes(address);
        if (candidate == null) return false;
        for (TrustedProxy proxy : trustedProxies) {
            if (proxy.matches(candidate)) return true;
        }
        return false;
    }

    private static List<TrustedProxy> parseTrustedProxies(String configured) {
        List<TrustedProxy> parsed = new ArrayList<>();
        if (configured == null || configured.isBlank()) return List.copyOf(parsed);
        for (String entry : configured.split(",")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) continue;
            TrustedProxy proxy = TrustedProxy.parse(trimmed);
            if (proxy != null) parsed.add(proxy);
        }
        return List.copyOf(parsed);
    }

    private static byte[] addressBytes(String address) {
        // Literal addresses only: getByName would otherwise resolve a hostname
        // out of a header, turning a rate-limit lookup into a DNS request.
        if (address == null || address.isBlank()) return null;
        String cleaned = address.startsWith("[") && address.endsWith("]")
                ? address.substring(1, address.length() - 1) : address;
        int zone = cleaned.indexOf('%');
        if (zone >= 0) cleaned = cleaned.substring(0, zone);
        if (!cleaned.matches("[0-9.]+|[0-9a-fA-F:]+")) return null;
        try {
            return InetAddress.getByName(cleaned).getAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    /** A trusted peer, either a single literal address or a CIDR block. */
    private record TrustedProxy(byte[] network, int prefixBits) {
        static TrustedProxy parse(String entry) {
            int slash = entry.indexOf('/');
            String host = slash < 0 ? entry : entry.substring(0, slash);
            byte[] network = addressBytes(host);
            if (network == null) return null;
            int prefixBits = network.length * 8;
            if (slash >= 0) {
                try {
                    prefixBits = Integer.parseInt(entry.substring(slash + 1).trim());
                } catch (NumberFormatException e) {
                    return null;
                }
                if (prefixBits < 0 || prefixBits > network.length * 8) return null;
            }
            return new TrustedProxy(network, prefixBits);
        }

        boolean matches(byte[] candidate) {
            if (candidate.length != network.length) return false;
            int fullBytes = prefixBits / 8;
            for (int i = 0; i < fullBytes; i++) {
                if (candidate[i] != network[i]) return false;
            }
            int remainingBits = prefixBits % 8;
            if (remainingBits == 0) return true;
            int mask = 0xFF << (8 - remainingBits);
            return (candidate[fullBytes] & mask) == (network[fullBytes] & mask);
        }

        @Override public boolean equals(Object other) {
            return other instanceof TrustedProxy proxy
                    && prefixBits == proxy.prefixBits && Arrays.equals(network, proxy.network);
        }

        @Override public int hashCode() {
            return Arrays.hashCode(network) * 31 + prefixBits;
        }
    }

    private static final class Window {
        final long minute;
        final AtomicInteger count = new AtomicInteger();

        Window(long minute) {
            this.minute = minute;
        }
    }
}
