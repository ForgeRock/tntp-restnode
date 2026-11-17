package org.forgerock.openam.auth.nodes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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
    private static String url;
    private static String[] identityA;
    private static String[] identityB;

    @BeforeAll
    static void setUp() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/echo", ex -> {
            byte[] body = "{}".getBytes();
            ex.sendResponseHeaders(200, body.length);
            try (var os = ex.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();
        url = "http://127.0.0.1:" + server.getAddress().getPort() + "/echo";
        identityA = generateIdentity("a");
        identityB = generateIdentity("b");
    }

    @AfterAll
    static void tearDown() {
        RESTNodeV2.clearClientCache();
        server.stop(0);
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
    void v2ShutsDownEvictedClients() throws Exception {
        // HttpClient.shutdown() exists from JDK 21; on 17 evicted clients are left to the garbage collector
        assumeTrue(Runtime.version().feature() >= 21, "needs JDK 21+");
        Set<String> before = clientThreadPrefixes();

        for (int timeout = 1; timeout <= RESTNodeV2.MAX_CACHED_CLIENTS + 8; timeout++) {
            TestConfig config = new TestConfig();
            config.timeout = timeout;
            assertEquals("2xx", new RESTNodeV2(config).process(context()).outcome);
        }

        Set<String> live = liveClientsCreatedSince(before);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (live.size() > RESTNodeV2.MAX_CACHED_CLIENTS && System.nanoTime() < deadline) {
            Thread.sleep(50);
            live = liveClientsCreatedSince(before);
        }
        assertEquals(RESTNodeV2.MAX_CACHED_CLIENTS, live.size(), "evicted clients should stop their threads");
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
        boolean usemTLS;
        String publicCert = "";
        String privateKey = "";
        boolean disableCertChecks;
        int timeout = 30;
        boolean basicAuthn;
        boolean logRequest;

        public String restURL() { return restURL; }
        public boolean usemTLS() { return usemTLS; }
        public String publicCert() { return publicCert; }
        public String privateKey() { return privateKey; }
        public boolean disableCertChecks() { return disableCertChecks; }
        public int timeout() { return timeout; }
        public boolean basicAuthn() { return basicAuthn; }
        public String basicAuthnUsername() { return "alice"; }
        public String basicAuthnPassword() { return "s3cret"; }
        public boolean logRequest() { return logRequest; }
        public List<String> responseCodes() { return List.of("2xx"); }
        public Map<String, String> jpToSSMapper() { return Map.of(); }
        public Map<String, String> jpToOutcomeMapper() { return Map.of(); }
    }

    private static RESTNode.Config v1Config() {
        return new RESTNode.Config() {
            public String restURL() { return url; }
            public List<String> responseCodes() { return List.of("2xx"); }
            public Map<String, String> jpToSSMapper() { return Map.of(); }
            public Map<String, String> jpToOutcomeMapper() { return Map.of(); }
        };
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

    private static Set<String> clientThreadPrefixes() {
        return Thread.getAllStackTraces().keySet().stream()
                .map(Thread::getName)
                .filter(n -> n.matches("HttpClient-\\d+-.*"))
                .map(n -> n.replaceFirst("(HttpClient-\\d+)-.*", "$1"))
                .collect(Collectors.toSet());
    }

    private static Set<String> liveClientsCreatedSince(Set<String> before) {
        Set<String> live = clientThreadPrefixes();
        live.removeAll(before);
        return live;
    }

    private static int unusedPort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
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
