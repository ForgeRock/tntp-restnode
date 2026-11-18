package org.forgerock.openam.auth.nodes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.upgrade.NoUpgrades;
import org.forgerock.openam.auth.node.api.upgrade.NodeVersionUpgrader;
import org.forgerock.openam.auth.node.api.upgrade.exception.InvalidUpgradeConfigException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import com.sun.net.httpserver.HttpServer;

/**
 * AM builds a new node instance for every evaluation (AuthTreeExecutor -> AuthNodeFactory.createNode),
 * so these tests build a new node for every request too.
 */
class HttpClientReuseTest {

    private static final int REQUESTS = 50;

    @TempDir
    static Path tempDir;

    private static HttpServer server;
    private static RawServer rawServer;
    private static String baseUrl;
    private static String url;
    private static String[] identityA;
    private static String[] identityB;
    private static final AtomicReference<String> recordedMethod = new AtomicReference<>();
    private static final AtomicReference<String> recordedBody = new AtomicReference<>();

    @BeforeAll
    static void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/echo", ex -> respond(ex, 200, "{}"));
        server.createContext("/bad-gateway", ex -> respond(ex, 502, "<html><body><h1>502 Bad Gateway</h1></body></html>"));
        server.createContext("/unavailable", ex -> respond(ex, 503, ""));
        server.createContext("/failed", ex -> respond(ex, 200, "[{\"status\":\"failed\"}]"));
        server.createContext("/record", ex -> {
            recordedMethod.set(ex.getRequestMethod());
            recordedBody.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            respond(ex, 200, "{}");
        });
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        url = baseUrl + "/echo";
        rawServer = new RawServer();
        identityA = generateIdentity("a");
        identityB = generateIdentity("b");
    }

    @AfterAll
    static void tearDown() throws IOException {
        RESTNodeV2.clearClientCache();
        server.stop(0);
        rawServer.close();
    }

    @BeforeEach
    void clearCache() {
        RESTNodeV2.clearClientCache();
    }

    @Test
    void v2SharesOneClientAcrossNodeInstances() throws Exception {
        Set<String> before = clientThreadPrefixes();

        for (int i = 0; i < REQUESTS; i++) {
            assertEquals("2xx", new RESTNodeV2(new TestConfig()).process(context()).outcome);
        }

        assertEquals(1, RESTNodeV2.cachedClientCount());
        Set<String> created = clientThreadPrefixes();
        created.removeAll(before);
        assertEquals(1, created.size(), "V2 should create exactly one client's threads, saw " + created);
    }

    @Test
    void v2KeepsSeparateClientsPerTlsSettings() throws Exception {
        TestConfig plain = new TestConfig();
        TestConfig longerTimeout = new TestConfig();
        longerTimeout.timeout = 31;
        TestConfig insecure = new TestConfig();
        insecure.disableCertChecks = true;

        for (int i = 0; i < 3; i++) {
            for (TestConfig config : List.of(plain, longerTimeout, insecure)) {
                assertEquals("2xx", new RESTNodeV2(config).process(context()).outcome);
            }
        }

        assertEquals(3, RESTNodeV2.cachedClientCount());
    }

    @Test
    void v2ReusesClientWhileHydratedCertificateRepeats() throws Exception {
        TestConfig dynamic = new TestConfig();
        dynamic.usemTLS = true;
        dynamic.publicCert = "${cert}";
        dynamic.privateKey = "${key}";

        for (int i = 0; i < 5; i++) {
            assertEquals("2xx", new RESTNodeV2(dynamic).process(context(identityA)).outcome);
        }
        assertEquals(1, RESTNodeV2.cachedClientCount());

        assertEquals("2xx", new RESTNodeV2(dynamic).process(context(identityB)).outcome);
        assertEquals(2, RESTNodeV2.cachedClientCount());
    }

    @Test
    void v2DynamicCertMissingFromSharedStateGoesToErrorWithoutCaching() throws Exception {
        TestConfig dynamic = new TestConfig();
        dynamic.usemTLS = true;
        dynamic.publicCert = "${cert}";
        dynamic.privateKey = "${key}";

        assertEquals("ERROR", new RESTNodeV2(dynamic).process(context()).outcome);
        assertEquals(0, RESTNodeV2.cachedClientCount());
    }

    @Test
    void cacheKeyUsesDigestOfKeyMaterial() {
        String keyA = RESTNodeV2.clientCacheKey(true, identityA[0], identityA[1], false, 30);

        assertEquals(keyA, RESTNodeV2.clientCacheKey(true, identityA[0], identityA[1], false, 30));
        assertNotEquals(keyA, RESTNodeV2.clientCacheKey(true, identityB[0], identityB[1], false, 30));
        assertNotEquals(keyA, RESTNodeV2.clientCacheKey(true, identityA[0], identityA[1], true, 30));
        assertNotEquals(keyA, RESTNodeV2.clientCacheKey(true, identityA[0], identityA[1], false, 31));
        assertFalse(keyA.contains("PRIVATE KEY"), keyA);
    }

    @Test
    void v2CacheIsBounded() throws Exception {
        for (int timeout = 1; timeout <= RESTNodeV2.MAX_CACHED_CLIENTS + 8; timeout++) {
            TestConfig config = new TestConfig();
            config.timeout = timeout;
            assertEquals("2xx", new RESTNodeV2(config).process(context()).outcome);
        }

        assertEquals(RESTNodeV2.MAX_CACHED_CLIENTS, RESTNodeV2.cachedClientCount());
    }

    @Test
    void evictedClientStillServesACallerThatAlreadyFetchedIt() throws Exception {
        RESTNodeV2.ClientCache cache = new RESTNodeV2.ClientCache(1);
        HttpClient fetched = cache.get("a", HttpClient::newHttpClient);

        cache.get("b", HttpClient::newHttpClient); // evicts "a" before its caller has sent anything

        assertEquals(1, cache.size());
        HttpResponse<String> response = fetched.send(HttpRequest.newBuilder(URI.create(url)).build(),
                HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode());
    }

    @Test
    void clientCacheBuildsEachKeyOnceWithoutBlockingOtherKeys() throws Exception {
        RESTNodeV2.ClientCache cache = new RESTNodeV2.ClientCache(4);
        CountDownLatch slowBuildStarted = new CountDownLatch(1);
        CountDownLatch releaseSlowBuild = new CountDownLatch(1);
        AtomicInteger slowBuilds = new AtomicInteger();
        HttpClient slowClient = HttpClient.newHttpClient();
        Callable<HttpClient> slowFactory = () -> {
            slowBuilds.incrementAndGet();
            slowBuildStarted.countDown();
            releaseSlowBuild.await();
            return slowClient;
        };
        ExecutorService pool = Executors.newFixedThreadPool(4);
        try {
            List<Future<HttpClient>> slowCallers = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                slowCallers.add(pool.submit(() -> cache.get("slow", slowFactory)));
            }
            assertTrue(slowBuildStarted.await(5, TimeUnit.SECONDS));

            // Another key is served while the first key's build is still running
            HttpClient fastClient = HttpClient.newHttpClient();
            assertSame(fastClient, assertTimeoutPreemptively(Duration.ofSeconds(2),
                    () -> cache.get("fast", () -> fastClient)));

            releaseSlowBuild.countDown();
            for (Future<HttpClient> caller : slowCallers) {
                assertSame(slowClient, caller.get(5, TimeUnit.SECONDS));
            }
            assertEquals(1, slowBuilds.get(), "concurrent first requests for a key should share one build");
        } finally {
            releaseSlowBuild.countDown();
            pool.shutdownNow();
        }
    }

    @Test
    void clientCacheDoesNotKeepAFailedBuild() throws Exception {
        RESTNodeV2.ClientCache cache = new RESTNodeV2.ClientCache(4);
        IllegalStateException failure = new IllegalStateException("bad key material");

        assertSame(failure, assertThrows(IllegalStateException.class, () -> cache.get("a", () -> {
            throw failure;
        })));
        assertEquals(0, cache.size());

        HttpClient client = HttpClient.newHttpClient();
        assertSame(client, cache.get("a", () -> client));
    }

    /**
     * The server closes a pooled connection without answering, as if its idle timeout had just expired. The JDK
     * retries GET itself; the node retries PUT and DELETE, and POST and PATCH only when Retry POST and PATCH is on.
     */
    @ParameterizedTest(name = "{0}, retryPostAndPatch={1}")
    @CsvSource({
            "GET,    false, 2xx,   3",
            "PUT,    false, 2xx,   3",
            "DELETE, false, 2xx,   3",
            "POST,   false, ERROR, 2",
            "PATCH,  false, ERROR, 2",
            "POST,   true,  2xx,   3",
            "PATCH,  true,  2xx,   3"
    })
    void v2RetriesAClosedPooledConnectionOnlyWhenSafeToRepeat(RESTNodeV2.RequestMode method, boolean retryPostAndPatch,
            String outcome, int requests) throws Exception {
        String path = "/stale/" + method + "-" + retryPostAndPatch;
        TestConfig config = retryConfig(path, method, retryPostAndPatch);

        assertEquals("2xx", new RESTNodeV2(config).process(context()).outcome); // leaves a pooled connection
        assertEquals(outcome, new RESTNodeV2(config).process(context()).outcome);

        assertEquals(requests, rawServer.requests(path), "requests the server received");
    }

    /**
     * The server reads the request on a new connection and closes it without answering, as if it processed the
     * request and the reply was lost. The JDK reports this exactly as it reports a pooled connection closed as idle,
     * so sending the request again can deliver it twice: only PUT and DELETE are sent again unless the node allows it.
     */
    @ParameterizedTest(name = "{0}, retryPostAndPatch={1}")
    @CsvSource({
            "PUT,    false, 2xx,   2",
            "DELETE, false, 2xx,   2",
            "POST,   false, ERROR, 1",
            "PATCH,  false, ERROR, 1",
            "POST,   true,  2xx,   2",
            "PATCH,  true,  2xx,   2"
    })
    void v2RepeatsARequestWhoseReplyWasLostOnlyWhenSafeToRepeat(RESTNodeV2.RequestMode method, boolean retryPostAndPatch,
            String outcome, int requests) throws Exception {
        String path = "/lost-reply/" + method + "-" + retryPostAndPatch;
        TestConfig config = retryConfig(path, method, retryPostAndPatch);

        assertEquals(outcome, new RESTNodeV2(config).process(context()).outcome);

        assertEquals(requests, rawServer.requests(path), "requests the server received");
    }

    /**
     * Once the timeout has passed a retry could only time out, possibly after delivering the request again. Failures
     * other than a connection closed before a response, such as a timeout, are never retried.
     */
    @Test
    void v2RetriesOnlyAConnectionClosedBeforeAResponseAndOnlyBeforeTheTimeout() {
        HttpRequest put = HttpRequest.newBuilder(URI.create(rawServer.url("/lost-reply/probe")))
                .PUT(HttpRequest.BodyPublishers.ofString("{}"))
                .build();
        HttpClient client = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
        IOException closed = assertThrows(IOException.class, () -> client.send(put, HttpResponse.BodyHandlers.discarding()));
        long beforeTimeout = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        long afterTimeout = System.nanoTime() - 1;

        assertTrue(RESTNodeV2.shouldRetry(RESTNodeV2.RequestMode.PUT, false, closed, beforeTimeout), closed.toString());
        assertFalse(RESTNodeV2.shouldRetry(RESTNodeV2.RequestMode.PUT, false, closed, afterTimeout));
        assertFalse(RESTNodeV2.shouldRetry(RESTNodeV2.RequestMode.POST, true, closed, afterTimeout));
        assertFalse(RESTNodeV2.shouldRetry(RESTNodeV2.RequestMode.PUT, false,
                new HttpTimeoutException("request timed out"), beforeTimeout));
    }

    @Test
    void v2TimeoutCoversAStalledResponseBody() {
        TestConfig config = new TestConfig();
        config.restURL = rawServer.url("/stall");
        config.timeout = 1;
        TreeContext context = context();

        long start = System.nanoTime();
        String outcome = assertTimeoutPreemptively(Duration.ofSeconds(10), () -> new RESTNodeV2(config).process(context).outcome);
        long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

        assertEquals("ERROR", outcome);
        assertTrue(elapsedMillis < 5000, "a 1 s timeout took " + elapsedMillis + " ms");
        assertTrue(sharedValueEndingWith(context.sharedState, "Exception").contains("timed out"), context.sharedState.toString());
    }

    @Test
    void v2NonJsonErrorPageReachesStatusCodeOutcome() throws Exception {
        TestConfig config = jsonHandlersConfig();

        config.restURL = baseUrl + "/bad-gateway";
        assertEquals("5xx", new RESTNodeV2(config).process(context()).outcome);

        config.restURL = baseUrl + "/unavailable";
        assertEquals("5xx", new RESTNodeV2(config).process(context()).outcome);
    }

    @Test
    void v2JsonHandlersStillApplyToJsonBodies() throws Exception {
        TestConfig config = jsonHandlersConfig();
        config.restURL = baseUrl + "/failed";
        TreeContext context = context();

        assertEquals("failed", new RESTNodeV2(config).process(context).outcome);
        assertEquals("failed", context.sharedState.get("status").asString());
    }

    @Test
    void v2StoresStackTraceInSharedStateOnlyWithDebugRequest() throws Exception {
        String unreachable = "http://127.0.0.1:" + unusedPort() + "/";

        TestConfig quiet = new TestConfig();
        quiet.restURL = unreachable;
        TreeContext quietContext = context();
        assertEquals("ERROR", new RESTNodeV2(quiet).process(quietContext).outcome);
        assertTrue(hasKeyEndingWith(quietContext.sharedState, "Exception"), quietContext.sharedState.toString());
        assertFalse(hasKeyEndingWith(quietContext.sharedState, "StackTrace"), quietContext.sharedState.toString());

        TestConfig debug = new TestConfig();
        debug.restURL = unreachable;
        debug.logRequest = true;
        TreeContext debugContext = context();
        assertEquals("ERROR", new RESTNodeV2(debug).process(debugContext).outcome);
        assertTrue(hasKeyEndingWith(debugContext.sharedState, "StackTrace"), debugContext.sharedState.toString());
    }

    @Test
    void v2RedactsAuthorizationInCurl() throws Exception {
        TestConfig config = new TestConfig();
        config.basicAuthn = true;
        config.logRequest = true;
        TreeContext context = context();

        assertEquals("2xx", new RESTNodeV2(config).process(context).outcome);

        String curl = context.sharedState.get("cURL").asString();
        assertTrue(curl.toLowerCase().contains("authorization: [redacted]"), curl);
        assertFalse(curl.contains(Base64.getEncoder().encodeToString("alice:s3cret".getBytes())), curl);
    }

    @Test
    void v2SendsBodyWithDeleteOnlyWhenEnabled() throws Exception {
        TestConfig delete = new TestConfig();
        delete.restURL = baseUrl + "/record";
        delete.requestMode = RESTNodeV2.RequestMode.DELETE;
        delete.payload = "{\"id\":42}";
        delete.logRequest = true;

        TreeContext withoutBody = context();
        assertEquals("2xx", new RESTNodeV2(delete).process(withoutBody).outcome);
        assertEquals("DELETE", recordedMethod.get());
        assertEquals("", recordedBody.get());
        assertFalse(withoutBody.sharedState.get("cURL").asString().contains("--data"));

        delete.deleteRequestBody = true;
        TreeContext withBody = context();
        assertEquals("2xx", new RESTNodeV2(delete).process(withBody).outcome);
        assertEquals("DELETE", recordedMethod.get());
        assertEquals("{\"id\":42}", recordedBody.get());
        assertTrue(withBody.sharedState.get("cURL").asString().contains("--data '{\"id\":42}'"));

        // Enabled with no body content: a plain DELETE
        delete.payload = "";
        assertEquals("2xx", new RESTNodeV2(delete).process(context()).outcome);
        assertEquals("", recordedBody.get());
    }

    @Test
    void upgraderIsDeclaredForVersion2() {
        assertEquals(RESTNodeV2.RESTNodeV2Upgrader.class, RESTNodeV2.class.getAnnotation(Node.VersionMetadata.class).upgrader());

        // AM refuses to install a node whose upgrader lacks this annotation
        NodeVersionUpgrader.UpgraderMetadata metadata =
                RESTNodeV2.RESTNodeV2Upgrader.class.getAnnotation(NodeVersionUpgrader.UpgraderMetadata.class);
        assertNotNull(metadata);
        assertEquals(2, metadata.version());
        assertEquals(NoUpgrades.class, metadata.previousUpgrader());
    }

    @Test
    void upgraderFillsEverySettingMissingFromAVersion1Config() throws Exception {
        // AM leaves settings with no stored value out of a node's configuration
        JsonValue v1 = JsonValue.json(JsonValue.object(
                JsonValue.field("_id", "node-1"),
                JsonValue.field("restURL", "https://api.example.com/users"),
                JsonValue.field("requestMode", "POST"),
                JsonValue.field("timeout", 10),
                JsonValue.field("responseCodes", List.of("2xx", "4xx")),
                JsonValue.field("payload", null)));

        JsonValue v2 = new RESTNodeV2.RESTNodeV2Upgrader().upgrade(v1);

        for (String setting : configSettings()) {
            assertTrue(v2.get(setting).isNotNull(), setting + " is missing from " + v2);
        }
        assertEquals("node-1", v2.get("_id").asString());
        assertEquals("https://api.example.com/users", v2.get("restURL").asString());
        assertEquals("POST", v2.get("requestMode").asString());
        assertEquals(10, v2.get("timeout").asInteger());
        assertEquals(List.of("2xx", "4xx"), v2.get("responseCodes").asList());
        assertEquals("", v2.get("payload").asString());
        assertEquals("JSON", v2.get("bodyType").asString());
        assertEquals(Map.of(), v2.get("jpToOutcomeMapper").asMap());
        assertFalse(v2.get("logRequest").asBoolean());
        assertFalse(v2.get("deleteRequestBody").asBoolean());
        assertFalse(v2.get("retryPostAndPatch").asBoolean(), "version 1 never sent a request twice");
    }

    @Test
    void upgraderKeepsSendBodyWithDeleteFromAVersion1Config() throws Exception {
        // Version 1 nodes from builds that have the setting already store it
        JsonValue v1 = JsonValue.json(JsonValue.object(
                JsonValue.field("restURL", "https://api.example.com/users/42"),
                JsonValue.field("requestMode", "DELETE"),
                JsonValue.field("deleteRequestBody", true)));

        assertTrue(new RESTNodeV2.RESTNodeV2Upgrader().upgrade(v1).get("deleteRequestBody").asBoolean());
    }

    @Test
    void upgraderRejectsAConfigThatIsNotAnObject() {
        assertThrows(InvalidUpgradeConfigException.class,
                () -> new RESTNodeV2.RESTNodeV2Upgrader().upgrade(JsonValue.json(null)));
    }

    @Test
    void v1CreatesNewClientPerRequest() throws Exception {
        Set<String> before = clientThreadPrefixes();

        for (int i = 0; i < REQUESTS; i++) {
            assertEquals("2xx", new RESTNode(v1Config()).process(context()).outcome);
        }

        Set<String> created = clientThreadPrefixes();
        created.removeAll(before);
        System.out.println("V1 distinct HttpClient thread prefixes after " + REQUESTS + " requests: " + created.size());
        assertTrue(created.size() > 1, "V1 baseline should leak one client per request, saw " + created.size());
    }

    /** Node defaults pointed at the test server; tests change what they need. */
    private static class TestConfig implements RESTNodeV2.Config {
        String restURL = url;
        RESTNodeV2.RequestMode requestMode = RESTNodeV2.RequestMode.GET;
        String payload = "";
        boolean usemTLS;
        String publicCert = "";
        String privateKey = "";
        boolean disableCertChecks;
        int timeout = 30;
        boolean basicAuthn;
        boolean logRequest;
        boolean deleteRequestBody;
        boolean retryPostAndPatch;
        List<String> responseCodes = List.of("2xx");
        Map<String, String> jpToSSMapper = Map.of();
        Map<String, String> jpToOutcomeMapper = Map.of();

        public String restURL() { return restURL; }
        public RESTNodeV2.RequestMode requestMode() { return requestMode; }
        public String payload() { return payload; }
        public boolean usemTLS() { return usemTLS; }
        public String publicCert() { return publicCert; }
        public String privateKey() { return privateKey; }
        public boolean disableCertChecks() { return disableCertChecks; }
        public int timeout() { return timeout; }
        public boolean basicAuthn() { return basicAuthn; }
        public String basicAuthnUsername() { return "alice"; }
        public String basicAuthnPassword() { return "s3cret"; }
        public boolean logRequest() { return logRequest; }
        public boolean deleteRequestBody() { return deleteRequestBody; }
        public boolean retryPostAndPatch() { return retryPostAndPatch; }
        public List<String> responseCodes() { return responseCodes; }
        public Map<String, String> jpToSSMapper() { return jpToSSMapper; }
        public Map<String, String> jpToOutcomeMapper() { return jpToOutcomeMapper; }
    }

    /** A request with a body to a path on the raw server. */
    private static TestConfig retryConfig(String path, RESTNodeV2.RequestMode method, boolean retryPostAndPatch) {
        TestConfig config = new TestConfig();
        config.restURL = rawServer.url(path);
        config.requestMode = method;
        config.payload = "{\"a\":1}";
        config.retryPostAndPatch = retryPostAndPatch;
        return config;
    }

    /** Both JSON handlers configured, with a status code outcome to fall back to. */
    private static TestConfig jsonHandlersConfig() {
        TestConfig config = new TestConfig();
        config.responseCodes = List.of("2xx", "5xx");
        config.jpToSSMapper = Map.of("status", "$[0].status");
        config.jpToOutcomeMapper = Map.of("failed", "$[?(@.status == 'failed')]");
        return config;
    }

    private static RESTNode.Config v1Config() {
        return new RESTNode.Config() {
            public String restURL() { return url; }
            public List<String> responseCodes() { return List.of("2xx"); }
            public Map<String, String> jpToSSMapper() { return Map.of(); }
            public Map<String, String> jpToOutcomeMapper() { return Map.of(); }
        };
    }

    private static Set<String> configSettings() {
        return Arrays.stream(RESTNodeV2.Config.class.getMethods())
                .filter(method -> method.isAnnotationPresent(Attribute.class))
                .map(Method::getName)
                .collect(Collectors.toSet());
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static TreeContext context() {
        return context(JsonValue.object());
    }

    private static TreeContext context(String[] identity) {
        return context(JsonValue.object(JsonValue.field("cert", identity[0]), JsonValue.field("key", identity[1])));
    }

    private static TreeContext context(Map<String, Object> sharedState) {
        return new TreeContext.Builder()
                .sharedState(JsonValue.json(sharedState))
                .transientState(JsonValue.json(JsonValue.object()))
                .build();
    }

    private static boolean hasKeyEndingWith(JsonValue state, String suffix) {
        return state.keys().stream().anyMatch(k -> k.endsWith(suffix));
    }

    private static String sharedValueEndingWith(JsonValue state, String suffix) {
        return state.keys().stream().filter(k -> k.endsWith(suffix)).findFirst()
                .map(k -> state.get(k).asString()).orElse("");
    }

    private static Set<String> clientThreadPrefixes() {
        return Thread.getAllStackTraces().keySet().stream()
                .map(Thread::getName)
                .filter(n -> n.matches("HttpClient-\\d+-.*"))
                .map(n -> n.replaceFirst("(HttpClient-\\d+)-.*", "$1"))
                .collect(Collectors.toSet());
    }

    private static int unusedPort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    /**
     * Minimal HTTP/1.1 server for connection-level behaviour HttpServer cannot produce. It counts the requests it reads
     * in full, by path. {@code /stale/...} answers the first request on a connection and closes the connection,
     * unanswered, on the next one. {@code /lost-reply/...} closes the connection without answering the first request
     * to its path, and answers later ones. {@code /stall} sends the response headers and part of the body, then sends
     * nothing more until the client goes away.
     */
    private static final class RawServer implements AutoCloseable {

        private final Map<String, AtomicInteger> requests = new ConcurrentHashMap<>();
        private final ServerSocket socket;

        RawServer() throws IOException {
            socket = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            Thread acceptor = new Thread(this::accept, "raw-server");
            acceptor.setDaemon(true);
            acceptor.start();
        }

        String url(String path) {
            return "http://127.0.0.1:" + socket.getLocalPort() + path;
        }

        int requests(String path) {
            AtomicInteger count = requests.get(path);
            return count == null ? 0 : count.get();
        }

        private void accept() {
            while (!socket.isClosed()) {
                try {
                    Socket connection = socket.accept();
                    Thread handler = new Thread(() -> handle(connection), "raw-server-connection");
                    handler.setDaemon(true);
                    handler.start();
                } catch (IOException e) {
                    return;
                }
            }
        }

        private void handle(Socket connection) {
            try (connection) {
                InputStream in = new BufferedInputStream(connection.getInputStream());
                OutputStream out = connection.getOutputStream();
                for (int served = 0; ; served++) {
                    String head = readHead(in);
                    if (head == null) {
                        return;
                    }
                    in.readNBytes(contentLength(head));
                    String path = head.split(" ")[1];
                    int count = requests.computeIfAbsent(path, p -> new AtomicInteger()).incrementAndGet();
                    if (path.equals("/stall")) {
                        out.write("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{\"partial\":".getBytes(StandardCharsets.US_ASCII));
                        out.flush();
                        while (in.read() != -1) {
                            // hold the response open until the client closes the connection
                        }
                        return;
                    }
                    if (path.startsWith("/stale/") && served > 0) {
                        return; // as if the server's idle timeout had just closed the pooled connection
                    }
                    if (path.startsWith("/lost-reply/") && count == 1) {
                        return; // as if the server processed the request and the reply was lost
                    }
                    out.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                }
            } catch (IOException e) {
                // client went away
            }
        }

        private static String readHead(InputStream in) throws IOException {
            StringBuilder head = new StringBuilder();
            int b;
            while ((b = in.read()) != -1) {
                head.append((char) b);
                if (head.length() >= 4 && head.lastIndexOf("\r\n\r\n") == head.length() - 4) {
                    return head.toString();
                }
            }
            return null;
        }

        private static int contentLength(String head) {
            for (String line : head.split("\r\n")) {
                if (line.toLowerCase().startsWith("content-length:")) {
                    return Integer.parseInt(line.substring("content-length:".length()).trim());
                }
            }
            return 0;
        }

        @Override
        public void close() throws IOException {
            socket.close();
        }
    }

    /** Self-signed RSA certificate and PKCS#8 key as PEM strings, generated with the JDK's keytool. */
    private static String[] generateIdentity(String alias) throws Exception {
        Path keystore = tempDir.resolve(alias + ".p12");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        Process process = new ProcessBuilder(keytool, "-genkeypair", "-alias", alias, "-keyalg", "RSA",
                "-keysize", "2048", "-dname", "CN=" + alias, "-validity", "1", "-storetype", "PKCS12",
                "-keystore", keystore.toString(), "-storepass", "changeit", "-keypass", "changeit")
                .redirectErrorStream(true)
                .start();
        String output = new String(process.getInputStream().readAllBytes());
        assertEquals(0, process.waitFor(), "keytool failed: " + output);

        KeyStore store = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(keystore)) {
            store.load(in, "changeit".toCharArray());
        }
        Certificate cert = store.getCertificate(alias);
        Key key = store.getKey(alias, "changeit".toCharArray());
        Base64.Encoder pem = Base64.getMimeEncoder(64, "\n".getBytes());
        return new String[] {
                "-----BEGIN CERTIFICATE-----\n" + pem.encodeToString(cert.getEncoded()) + "\n-----END CERTIFICATE-----",
                "-----BEGIN PRIVATE KEY-----\n" + pem.encodeToString(key.getEncoded()) + "\n-----END PRIVATE KEY-----"
        };
    }
}
