/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */



package org.forgerock.openam.auth.nodes;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.node.api.upgrade.NoUpgrades;
import org.forgerock.openam.auth.node.api.upgrade.NodeVersionUpgrader;
import org.forgerock.openam.auth.node.api.upgrade.exception.InvalidUpgradeConfigException;
import org.forgerock.util.i18n.PreferredLocales;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.InvalidPathException;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.JsonPathException;
import com.jayway.jsonpath.Option;
import com.jayway.jsonpath.PathNotFoundException;
import com.sun.identity.sm.RequiredValueValidator;

@Node.Metadata(outcomeProvider = RESTNodeV2.RESTOutcomeProvider.class,
        configClass = RESTNodeV2.Config.class,
        tags            = {"marketplace", "trustnetwork"}
)
@Node.VersionMetadata(name = "RESTNode", version = 2, upgrader = RESTNodeV2.RESTNodeV2Upgrader.class)
public class RESTNodeV2 implements Node {

    private static final Logger logger = LoggerFactory.getLogger(RESTNodeV2.class);
    private static final String loggerPrefix = "[RESTNodeV2]" + RESTNodePlugin.logAppender;

    private final Config config;
    private static final String BUNDLE = RESTNodeV2.class.getName();

    private static final String NOMATCHRESPONSE = "NOMATCHRESPONSE";
    private static final String ERROR = "ERROR";

    // AM builds a new node instance for every evaluation (AuthTreeExecutor -> AuthNodeFactory.createNode),
    // so an HttpClient held in an instance field would still be rebuilt on every request. Clients are
    // cached per class instead, keyed by everything that shapes a client (mTLS material, trust mode,
    // connect timeout), and shared by every RESTNodeV2 with the same settings.
    static final int MAX_CACHED_CLIENTS = 32;

    private static final ClientCache CLIENT_CACHE = new ClientCache(MAX_CACHED_CLIENTS);

    // The JDK's message when a connection closes before any byte of the response arrives (same on JDK 17 to 26). It is
    // the same whether the connection was pooled or new, and whether or not the server had read the request.
    private static final String NO_RESPONSE_BYTES = "header parser received no bytes";

    public enum RequestMode {
        GET, POST, PUT, DELETE, PATCH, HEAD
    }

    public enum BodyType {
        XWWWFORMURLENCODED, JSON, XML, PLAIN, CUSTOM
    }

    /**
     * Configuration for the node.
     */

    public interface Config {
        @Attribute(order = 100, validators = { RequiredValueValidator.class })
        default String restURL() { return ""; }

        @Attribute(order = 200, validators = { RequiredValueValidator.class })
        default RequestMode requestMode() {
            return RequestMode.GET;
        }

        @Attribute(order = 300)
        default Map<String, String> queryParamsMap() {
            return Collections.emptyMap();
        }

        @Attribute(order = 400)
        default Map<String, String> headersMap() {
            return Collections.emptyMap();
        }

        @Attribute(order = 450)
        default boolean basicAuthn() { return false; }

        @Attribute(order = 460)
        default String basicAuthnUsername() { return ""; }

        @Attribute(order = 470)
        default String basicAuthnPassword() { return ""; }

        @Attribute(order = 500)
        default String payload() { return ""; }

        @Attribute(order = 550, validators = { RequiredValueValidator.class })
        default BodyType bodyType() {
            return BodyType.JSON;
        }

        @Attribute(order = 600)
        default boolean usemTLS() { return false; }

        @Attribute(order = 700)
        default String publicCert() { return "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"; }

        @Attribute(order = 800)
        default String privateKey() { return "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"; }

        @Attribute(order = 900)
        default boolean disableCertChecks() { return false; }

        @Attribute(order = 1000)
        default int timeout() { return 30; }

        @Attribute(order = 1050)
        default boolean retryPostAndPatch() { return false; }

        @Attribute(order = 1100)
        List<String> responseCodes();

        @Attribute(order = 1200)
        default String statusCodeReturn() { return ""; }

        @Attribute(order = 1300)
        default String bodyReturn() { return ""; }

        @Attribute(order = 1400)
        Map<String, String> jpToSSMapper();

        @Attribute(order = 1500)
        Map<String, String> jpToOutcomeMapper();

        @Attribute(order = 1600)
        default boolean logRequest() { return false; }

        @Attribute(order = 1700)
        default boolean deleteRequestBody() { return false; }

        @Attribute(order = 1800)
        default boolean getRequestBody() { return false; }
    }


    /**
     * Guice constructor.
     * @param config The node configuration.
     * @throws NodeProcessException If there is an error reading the configuration.
     */
    @Inject
    public RESTNodeV2(@Assisted Config config) throws NodeProcessException {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        String url = null;
        try {
            logger.debug(loggerPrefix + "Started");

            // Construct URL with query parameters including variable substitution from sharedState
            url = hydrate(context,(config.restURL() + getQueryString(context, config.queryParamsMap())));

            // Shared httpClient for this node's TLS settings (mTLS certs, certificate checking, connect timeout)
            HttpClient httpClient = getHttpClient(context);

            // Add request type, payload, timeouts, headers and send
            HttpResponse<String> response = callREST(context, config.requestMode(), httpClient, url, config.headersMap(), config.bodyType(), hydrate(context,config.payload()), config.timeout());

            if (response == null) {
                context.getStateFor(this).putShared("DebugResponse","ERROR");
                return Action.goTo(ERROR).build();
            } else {
                if ((config.statusCodeReturn() != null) && (config.statusCodeReturn() != "")) context.getStateFor(this).putShared(config.statusCodeReturn(),response.statusCode());
                if ((config.bodyReturn() != null) && (config.bodyReturn() != "")) context.getStateFor(this).putShared(config.bodyReturn(),response.body());

                // Parsed once, for both JSON handlers, and only when one is configured
                Object document = config.jpToSSMapper().isEmpty() && config.jpToOutcomeMapper().isEmpty()
                        ? null : parseJson(response.body());
                processResponse(context, document);

                // Choose dynamic outcome if provided in config, e.g., response code 200, 401, etc
                String outcome = calculateOutcome(config.responseCodes(), response.statusCode(), context, document);

                return Action.goTo(outcome).build();
            }

        } catch (Exception ex) {
            if (ex instanceof IOException) {
                // Network failures (connect/request timeouts, refused or reset connections, TLS handshake
                // failures) are expected under load or during an outage: log one line and keep the stack
                // trace at DEBUG so a failure surge cannot stall the stdout pipe.
                logger.warn(loggerPrefix + "Request to " + describeTarget(url) + " failed: " + ex);
                logger.debug(loggerPrefix + "Request failure stack trace", ex);
            } else {
                if (ex instanceof InterruptedException) {
                    Thread.currentThread().interrupt();
                }
                logger.error(loggerPrefix + "Exception occurred", ex);
            }
            NodeState nodeState = context.getStateFor(this);
            nodeState.putShared(loggerPrefix + "Exception", ex.getMessage());
            if (config.logRequest()) {
                nodeState.putShared(loggerPrefix + "StackTrace", ExceptionUtils.getStackTrace(ex));
            }
            return Action.goTo(ERROR).build();
        }

    }

    /**
     * Return the shared HttpClient for this node's TLS settings, building it on first use. mTLS material
     * hydrated from sharedState is part of the cache key, so per-request certs are reused while they repeat.
     */
    private HttpClient getHttpClient(TreeContext context) throws Exception {
        boolean usemTLS = config.usemTLS();
        String publicCert = usemTLS ? hydrate(context, config.publicCert()) : null;
        String privateKey = usemTLS ? hydrate(context, config.privateKey()) : null;
        String key = clientCacheKey(usemTLS, publicCert, privateKey, config.disableCertChecks(), config.timeout());
        return CLIENT_CACHE.get(key, () -> getmTLShttpClient(publicCert, privateKey));
    }

    /**
     * Cache key covering every input that shapes an HttpClient. The mTLS cert and key enter as a SHA-256
     * digest so the cache does not hold another copy of the private key.
     */
    static String clientCacheKey(boolean usemTLS, String publicCert, String privateKey, boolean disableCertChecks, int connectTimeoutSeconds) {
        StringBuilder key = new StringBuilder()
                .append("mtls=").append(usemTLS)
                .append("|insecure=").append(disableCertChecks)
                .append("|connectTimeout=").append(connectTimeoutSeconds);
        if (usemTLS) {
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(String.valueOf(publicCert).getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0);
                digest.update(String.valueOf(privateKey).getBytes(StandardCharsets.UTF_8));
                key.append("|material=").append(Base64.getEncoder().encodeToString(digest.digest()));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 is not available", e); // required on every JDK
            }
        }
        return key.toString();
    }

    static int cachedClientCount() {
        return CLIENT_CACHE.size();
    }

    static void clearClientCache() {
        CLIENT_CACHE.clear();
    }

    /**
     * Bounded LRU of shared clients. A client is built outside the cache lock, so parsing mTLS material and creating
     * an SSLContext for one key never holds up requests for other keys, while concurrent first requests for the same
     * key wait for a single build. Evicted clients are not shut down: another thread may have fetched one and not yet
     * sent on it, and a shut-down client rejects new requests. The garbage collector reclaims them once unused.
     */
    static final class ClientCache {

        private final Map<String, CompletableFuture<HttpClient>> clients;

        ClientCache(int maxSize) {
            clients = new LinkedHashMap<String, CompletableFuture<HttpClient>>(16, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, CompletableFuture<HttpClient>> eldest) {
                    return size() > maxSize;
                }
            };
        }

        HttpClient get(String key, Callable<HttpClient> factory) throws Exception {
            CompletableFuture<HttpClient> client;
            boolean build;
            synchronized (clients) {
                client = clients.get(key);
                build = client == null;
                if (build) {
                    client = new CompletableFuture<>();
                    clients.put(key, client);
                }
            }
            if (build) {
                try {
                    client.complete(factory.call());
                } catch (Exception | Error e) {
                    // Not cached, so the next request with these settings tries again
                    synchronized (clients) {
                        clients.remove(key, client);
                    }
                    client.completeExceptionally(e);
                    throw e;
                }
            }
            try {
                return client.get();
            } catch (ExecutionException e) {
                // Another request's build for this key failed: fail with the same cause
                Throwable cause = e.getCause();
                if (cause instanceof Exception) {
                    throw (Exception) cause;
                }
                throw (Error) cause;
            }
        }

        int size() {
            synchronized (clients) {
                return clients.size();
            }
        }

        void clear() {
            synchronized (clients) {
                clients.clear();
            }
        }
    }

    /**
     * Scheme, host and port only: the hydrated URL can carry user data from shared state in its path or query.
     */
    private static String describeTarget(String url) {
        try {
            URI uri = URI.create(url);
            if (uri.getHost() == null) {
                return "<unknown host>";
            }
            return uri.getScheme() + "://" + uri.getHost() + (uri.getPort() == -1 ? "" : ":" + uri.getPort());
        } catch (RuntimeException e) {
            return "<unparseable URL>";
        }
    }


    //TODO JK - any reason not to throw the exception thrown in this method, instead of catching it and logging it here
    
    private void processResponse(TreeContext context, Object document) {
        NodeState nodeState = context.getStateFor(this);
        Set<String> keys = config.jpToSSMapper().keySet();

        if (document == null) {
            if (!keys.isEmpty()) {
                logger.debug(loggerPrefix + "Response body is not JSON, skipping the JSON Response Handler");
            }
            return;
        }

        for (Iterator<String> i = keys.iterator(); i.hasNext();) {
            String toSS = i.next();
            String thisJPath = config.jpToSSMapper().get(toSS);
            try {
                Object val = JsonPath.read(document, thisJPath);
                if (val instanceof java.util.LinkedHashMap) {
                    JSONObject json = new JSONObject((LinkedHashMap<String, Object>) val);
                    nodeState.putShared(toSS, json);
                } else if (val instanceof net.minidev.json.JSONArray) {
                    nodeState.putShared(toSS,((net.minidev.json.JSONArray)val));
                } else {
                    nodeState.putShared(toSS, val);
                }
            } catch (InvalidPathException e) { // includes PathNotFoundException
                logger.error(loggerPrefix + " " + e);
            }
        }
    }

    /**
     * The response body as a JSON object or array, or null for anything else, such as an empty body or a gateway's
     * HTML error page. The JSON handlers do not apply to those.
     */
    private static Object parseJson(String responseBody) {
        try {
            Object document = Configuration.defaultConfiguration().addOptions(Option.SUPPRESS_EXCEPTIONS).jsonProvider().parse(responseBody);
            return (document instanceof Map || document instanceof List) ? document : null;
        } catch (JsonPathException | IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Try to match response code to user configured outcomes. Supports wildcards such as 2xx, 3xx, etc.
     */
    private String calculateOutcome(List<String>outcomes, int statusCode, TreeContext context, Object document)
    {
        String result = null;
        String statusCodeStr = Integer.toString(statusCode);
        // Catch wildcards first
        for (String outcome : outcomes) {
            if (outcome.contains("xx") && (outcome.charAt(0) == statusCodeStr.charAt(0))) result = outcome;
        }
        // Override for explicit matches
        for (String outcome : outcomes) {
            if (outcome.equals(statusCodeStr)) result = outcome;
        }

        // Calculate outcomes based on JSONpath filters. If any filter matches, the corresponding outcome is used.
        // This superceeds any previous matching statusCode outcome. A body that is not JSON, or a filter that
        // cannot be applied to it, matches nothing, so an error page still reaches its status code outcome.

        Set<String> keys = document == null ? Collections.emptySet() : config.jpToOutcomeMapper().keySet();

        for (Iterator<String> i = keys.iterator(); i.hasNext();) {
            String toSS = i.next();
            String thisJPath = config.jpToOutcomeMapper().get(toSS);
            try {
                List<String> vals = JsonPath.read(document, thisJPath);
                if (vals.size() > 0) {
                    result = toSS;
                    break;  // Exit at first matching outcome
                }
            } catch (InvalidPathException e) { // includes PathNotFoundException
                logger.debug(loggerPrefix + "JSON outcome " + toSS + " did not match: " + e.getMessage());
            }
        }

        if (result == null)
            return NOMATCHRESPONSE;

        return result;
    }

    /**
     * Convert query string map to URL encoded query string
     */
    private String getQueryString(TreeContext context, Map<String, String> queryMap)
    {
        String result = "";
        Iterator<Map.Entry<String, String>> qmap = queryMap.entrySet().iterator(); 
        if (qmap.hasNext()) {
            Map.Entry<String, String> entry = qmap.next();
            result += "?" + entry.getKey() + "=" + entry.getValue();
            while (qmap.hasNext()) {
                entry = qmap.next(); 
                result += "&" + entry.getKey() + "=" + entry.getValue();
            }
        }
        return result;
    }


    /**
     * Process string to replace placeholder variables ${likethis} with values from sharedState
     * Values of the form ${variable.$.<jsonpath>} will be retrieved from shared state, and processed by JSONpath
     */
    private String hydrateVariable(TreeContext context, String input) {
        if (input.indexOf(".$.") > 0) {  // Use JSONpath substitution
            JsonValue thisJV = context.getStateFor(this).get(input.substring(0, input.indexOf('.')));

            // If shared state value is stringified JSON then unescape it so it can be parsed
            String thisJVStr;
            if (thisJV.isString()) thisJVStr = thisJV.asString().replace("\\\"","");
            else thisJVStr = thisJV.toString();

            Object document = Configuration.defaultConfiguration().addOptions(Option.SUPPRESS_EXCEPTIONS).jsonProvider().parse(thisJVStr);

            // Ignore (nullify) invalid JSON content
            try {

                Object val = JsonPath.read(document, input.substring(input.indexOf('.') + 1, input.length()));
                if (val instanceof java.util.LinkedHashMap) {
                    JSONObject json = new JSONObject((LinkedHashMap<String, Object>) val);
                    return json.toString();
                } else if (val instanceof net.minidev.json.JSONArray) {
                    return  ((net.minidev.json.JSONArray)val).toJSONString();
                } else {
                    return val.toString();
                }
            } catch (PathNotFoundException e) {
                logger.error(loggerPrefix + " " + e);
                return null;
            }

        } else { // Use simple string substitution
            JsonValue json = context.getStateFor(this).get(input);
            if (json.isString()) return context.getStateFor(this).get(input).asString().replace("\\\"","");
            else return context.getStateFor(this).get(input).toString();
        }
    }


    private String hydrate(TreeContext context, String source) {
        try {
            if (source != null) {
                String regex = "\\$\\{([^}]+)\\}";
                Pattern pattern = Pattern.compile(regex);

                int lastIndex = 0;
                StringBuilder output = new StringBuilder();
                Matcher matcher = pattern.matcher(source);
                while (matcher.find()) {
                    String found = hydrateVariable(context, matcher.group(1));
                    output.append(source, lastIndex, matcher.start())
                            .append(found);

                    lastIndex = matcher.end();
                }
                if (lastIndex < source.length()) {
                    output.append(source, lastIndex, source.length());
                }
                return output.toString();
            } else return "";
        } catch (NullPointerException | StringIndexOutOfBoundsException e) {
            return "";
        }
    }


    /**
     * Implementation of a certificate trustmanager to ignore invalid cert problems (wrong host, expired, etc)
     */
    private static final TrustManager insecureTrustManager = new X509ExtendedTrustManager() {
        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[0];
        }
        @Override
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException { }
        @Override
        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) throws CertificateException { }
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException { }
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException { }
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException { }
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException { }
    };


    private static final SecureRandom RANDOM = new SecureRandom();

    private static String getRandomString() {
        byte[] bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * Create httpClient with suitable config for mTLS, certs, ignore certs, etc.
     * publicCert and privateKey are already hydrated, and null when mTLS is off.
     */
	private HttpClient getmTLShttpClient(String publicCert, String privateKey) throws Exception {

		KeyManager[] keyManager = null;
		TrustManager[] trustManager = null;
		SSLParameters sslParam = new SSLParameters();

		// parse certificate

		if (config.usemTLS()) {

			final byte[] publicData = publicCert.replaceAll(" ", "\n").replaceAll("\nCERTIFICATE", " CERTIFICATE").getBytes();
			final byte[] privateData = Base64.getDecoder().decode(privateKey.replaceAll("-----BEGIN PRIVATE KEY-----", "").replaceAll("-----END PRIVATE KEY-----", "").replaceAll("\\s", ""));

			final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			final Collection<? extends Certificate> chain = certificateFactory.generateCertificates(new ByteArrayInputStream(publicData));

			logger.debug(loggerPrefix + "Successfully loaded the client cert certificate chain: " + String.join(" -> ", chain.stream().map(certificate -> {
				if (certificate instanceof X509Certificate) {
					final X509Certificate x509Cert = (X509Certificate) certificate;
					return x509Cert.getSubjectDN().toString();
				} else {
					return certificate.getType();
				}
			}).collect(Collectors.toList())));

			final Key key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateData));

			// place cert+key into KeyStore
			KeyStore clientKeyStore;
			clientKeyStore = KeyStore.getInstance("jks"); // Replace with "bcfks" for FIPS compliant keystore

			final char[] pwdChars = getRandomString().toCharArray();
			clientKeyStore.load(null, null);
			clientKeyStore.setKeyEntry("mtls-cert", key, pwdChars, chain.toArray(new Certificate[0]));

			// initialize KeyManagerFactory
			KeyManagerFactory keyMgrFactory = KeyManagerFactory.getInstance("SunX509");
			keyMgrFactory.init(clientKeyStore, pwdChars);
			keyManager = keyMgrFactory.getKeyManagers();

			sslParam.setNeedClientAuth(true);
		}

		if (config.disableCertChecks()) {
			trustManager = new TrustManager[] { insecureTrustManager };
		}

		// populate SSLContext with key manager
		SSLContext sslCtx = SSLContext.getInstance("TLSv1.2");
		sslCtx.init(keyManager, trustManager, null);

		// HTTP/1.1 because the client is shared. Over HTTP/2 all concurrent requests to a host become streams
		// on one connection, and once the server's stream limit is reached the JDK fails new requests with
		// "too many concurrent streams" instead of opening another connection. HTTP/1.1 pools connections.
		HttpClient client = HttpClient.newBuilder()
				.version(HttpClient.Version.HTTP_1_1)
				.connectTimeout(Duration.ofSeconds(config.timeout()))
				.sslContext(sslCtx)
				.sslParameters(sslParam)
				.build();

		return client;

	}

    /**
     * Call REST endpoint
     */
	private HttpResponse<String> callREST(TreeContext context, RequestMode requestMode, HttpClient httpClient, String url, Map<String, String> headersMap, BodyType bodyType, String payload, int timeout) throws Exception {

		HttpRequest.Builder requestBuilder;

		// Whether a GET or DELETE request should send the configured payload as its body. Each setting applies only to
		// requests of its own method.
		boolean hasPayload = payload != null && !payload.isEmpty();
		boolean sendBodyWithGet = requestMode == RequestMode.GET && config.getRequestBody() && hasPayload;
		boolean sendBodyWithDelete = requestMode == RequestMode.DELETE && config.deleteRequestBody() && hasPayload;

		switch (requestMode) {
		case POST:
			requestBuilder = HttpRequest.newBuilder().POST(HttpRequest.BodyPublishers.ofString(payload));
			break;
		case PUT:
			requestBuilder = HttpRequest.newBuilder().PUT(HttpRequest.BodyPublishers.ofString(payload));
			break;
		case DELETE:
			if (sendBodyWithDelete) {
				requestBuilder = HttpRequest.newBuilder().method("DELETE", HttpRequest.BodyPublishers.ofString(payload));
			} else {
				requestBuilder = HttpRequest.newBuilder().DELETE();
			}
			break;
		case PATCH:
			requestBuilder = HttpRequest.newBuilder().method("PATCH", HttpRequest.BodyPublishers.ofString(payload));
			break;
		case HEAD:
			requestBuilder = HttpRequest.newBuilder().method("HEAD", HttpRequest.BodyPublishers.ofString(payload));
			break;
		case GET:
		default:
			if (sendBodyWithGet) {
				requestBuilder = HttpRequest.newBuilder().method("GET", HttpRequest.BodyPublishers.ofString(payload));
			} else {
				requestBuilder = HttpRequest.newBuilder().GET();
			}
			break;
		}

		switch (bodyType) {
		case XWWWFORMURLENCODED:
			requestBuilder.header("content-type", "application/x-www-form-urlencoded");
			break;
		case JSON:
			requestBuilder.header("content-type", "application/json");
			break;
		case XML:
			requestBuilder.header("content-type", "text/xml");
			break;
		case PLAIN:
		default:
			requestBuilder.header("content-type", "text/plain");
			break;
		}

		for (Map.Entry<String, String> entry : headersMap.entrySet()) {
			requestBuilder.header(entry.getKey(), hydrate(context, entry.getValue()));
		}

		if (config.basicAuthn()) {
			String authHeader = "Basic " + Base64.getEncoder().encodeToString(hydrate(context, config.basicAuthnUsername() + ":" + config.basicAuthnPassword()).getBytes());
			requestBuilder.header("authorization", authHeader);
		}

		HttpRequest request = requestBuilder.uri(URI.create(url)).timeout(Duration.ofSeconds(timeout)).build();


        // Generate cURL encoded version of request as debug and add to sharedState.
        // String building is skipped entirely unless a debug consumer is attached.
        if (logger.isDebugEnabled() || config.logRequest()) {
            String curlRequest = "curl --location --request " + request.method();
            if (config.disableCertChecks()) curlRequest += " --insecure";
            if (config.usemTLS()) curlRequest += " --cert [CERTIFICATE] --key [KEY]";
            curlRequest += " '" + request.uri() + "'";
            for (Map.Entry<String,List<String>> entry : request.headers().map().entrySet()) {
                // Credentials stay out of debug logs and shared state, like the mTLS cert and key above
                String value = isCredentialHeader(entry.getKey()) ? "[REDACTED]" : entry.getValue().get(0);
                curlRequest += " -H '" + entry.getKey() + ": " + value + "'";
            }
            if (sendBodyWithGet || sendBodyWithDelete || (requestMode != RequestMode.GET && requestMode != RequestMode.DELETE)) curlRequest += " --data '" + payload + "'";
            logger.debug(loggerPrefix + "cURL equivalent request: " + curlRequest);
            if (config.logRequest()) context.getStateFor(this).putShared("cURL", curlRequest);
        }


        // Send request. The timeout covers the whole call, including a retry and reading the response body.
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeout);
        HttpResponse<String> response;
        try {
            response = send(httpClient, request, deadline);
        } catch (IOException e) {
            if (!shouldRetry(requestMode, config.retryPostAndPatch(), e, deadline)) {
                throw e;
            }
            logger.debug(loggerPrefix + "Connection closed before a response, retrying once: " + e);
            response = send(httpClient, request, deadline);
        }
        logger.debug(loggerPrefix + "HttpRequest response: " + response.statusCode());
        logger.debug(loggerPrefix + "HttpRequest response: " + response.body());

		return response;

	}

    /**
     * Send and read the whole response before the deadline. The request timeout alone stops counting once the
     * response headers arrive, so a server that sends headers and then stalls would hold the thread indefinitely.
     */
    private static HttpResponse<String> send(HttpClient httpClient, HttpRequest request, long deadline)
            throws IOException, InterruptedException {
        CompletableFuture<HttpResponse<String>> response = httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString());
        try {
            return response.get(deadline - System.nanoTime(), TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            response.cancel(true); // aborts the exchange and closes its connection
            throw new HttpTimeoutException("request timed out");
        } catch (InterruptedException e) {
            response.cancel(true);
            throw e;
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException) {
                throw (IOException) cause;
            }
            if (cause instanceof RuntimeException) {
                throw (RuntimeException) cause;
            }
            if (cause instanceof Error) {
                throw (Error) cause;
            }
            throw new IOException(cause);
        }
    }

    /**
     * Whether to send a failed request once more. Only one failure qualifies: the connection closed before any byte of
     * the response arrived. Usually the server had closed a pooled keep-alive connection as idle and never read the
     * request, but the JDK reports a server that read the request, acted on it and closed the connection without
     * answering in exactly the same way, so the request may already have taken effect. It is sent again only where that
     * is safe: PUT and DELETE are idempotent, and POST and PATCH are repeated only when Retry POST and PATCH is enabled.
     * GET and HEAD are left to the JDK, which retries them itself when a pooled connection closes. Once the timeout has
     * passed, a retry could only time out, possibly after delivering the request again, so the failure stands.
     */
    static boolean shouldRetry(RequestMode requestMode, boolean retryPostAndPatch, IOException failure, long deadline) {
        boolean safeToRepeat;
        switch (requestMode) {
            case PUT:
            case DELETE:
                safeToRepeat = true;
                break;
            case POST:
            case PATCH:
                safeToRepeat = retryPostAndPatch;
                break;
            default:
                safeToRepeat = false;
                break;
        }
        return safeToRepeat && deadline - System.nanoTime() > 0 && closedBeforeResponse(failure);
    }

    /**
     * True when the connection closed before any byte of the response arrived.
     */
    private static boolean closedBeforeResponse(IOException e) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (t.getMessage() != null && t.getMessage().contains(NO_RESPONSE_BYTES)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isCredentialHeader(String name) {
        return "authorization".equalsIgnoreCase(name) || "proxy-authorization".equalsIgnoreCase(name);
    }

    /**
     * AM leaves a setting with no stored value out of a node's configuration. Version 1 nodes have no Retry POST and
     * PATCH or Send Body with GET setting at all, and those from a build without Send Body with DELETE have no such
     * setting either. After an update the journey editor reports every setting missing from the upgraded configuration
     * as a missing required value, so each one is filled in with its default.
     */
    @NodeVersionUpgrader.UpgraderMetadata(version = 2, previousUpgrader = NoUpgrades.class)
    public static class RESTNodeV2Upgrader implements NodeVersionUpgrader {

        private static final Config DEFAULTS = new Config() {
            @Override
            public List<String> responseCodes() { return Collections.emptyList(); }
            @Override
            public Map<String, String> jpToSSMapper() { return Collections.emptyMap(); }
            @Override
            public Map<String, String> jpToOutcomeMapper() { return Collections.emptyMap(); }
        };

        @Override
        public JsonValue upgrade(JsonValue config) throws InvalidUpgradeConfigException {
            if (!config.isMap()) {
                throw new InvalidUpgradeConfigException();
            }
            putIfMissing(config, "restURL", DEFAULTS.restURL());
            putIfMissing(config, "requestMode", DEFAULTS.requestMode().name());
            putIfMissing(config, "queryParamsMap", new LinkedHashMap<>(DEFAULTS.queryParamsMap()));
            putIfMissing(config, "headersMap", new LinkedHashMap<>(DEFAULTS.headersMap()));
            putIfMissing(config, "basicAuthn", DEFAULTS.basicAuthn());
            putIfMissing(config, "basicAuthnUsername", DEFAULTS.basicAuthnUsername());
            putIfMissing(config, "basicAuthnPassword", DEFAULTS.basicAuthnPassword());
            putIfMissing(config, "payload", DEFAULTS.payload());
            putIfMissing(config, "bodyType", DEFAULTS.bodyType().name());
            putIfMissing(config, "usemTLS", DEFAULTS.usemTLS());
            putIfMissing(config, "publicCert", DEFAULTS.publicCert());
            putIfMissing(config, "privateKey", DEFAULTS.privateKey());
            putIfMissing(config, "disableCertChecks", DEFAULTS.disableCertChecks());
            putIfMissing(config, "timeout", DEFAULTS.timeout());
            putIfMissing(config, "retryPostAndPatch", DEFAULTS.retryPostAndPatch());
            putIfMissing(config, "responseCodes", new ArrayList<>(DEFAULTS.responseCodes()));
            putIfMissing(config, "statusCodeReturn", DEFAULTS.statusCodeReturn());
            putIfMissing(config, "bodyReturn", DEFAULTS.bodyReturn());
            putIfMissing(config, "jpToSSMapper", new LinkedHashMap<>(DEFAULTS.jpToSSMapper()));
            putIfMissing(config, "jpToOutcomeMapper", new LinkedHashMap<>(DEFAULTS.jpToOutcomeMapper()));
            putIfMissing(config, "logRequest", DEFAULTS.logRequest());
            putIfMissing(config, "deleteRequestBody", DEFAULTS.deleteRequestBody());
            putIfMissing(config, "getRequestBody", DEFAULTS.getRequestBody());
            return config;
        }

        private static void putIfMissing(JsonValue config, String setting, Object defaultValue) {
            if (config.get(setting).isNull()) {
                config.put(setting, defaultValue);
            }
        }
    }

    /**
     * Populate node outcomes based on configuration options
     */
    public static class RESTOutcomeProvider implements OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {

            List<Outcome> outcomes = new ArrayList<>();
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, RESTNodeV2.class.getClassLoader());

            try {
                outcomes = nodeAttributes.get("responseCodes").required()
                        .asList(String.class)
                        .stream()
                        .map(choice -> new Outcome(choice, choice))
                        .collect(Collectors.toList());
            } catch (JsonValueException e) {
                outcomes =  new ArrayList<>();
            }

            if (outcomes == null) outcomes = new ArrayList<>();

			if (nodeAttributes!= null && nodeAttributes.get("jpToOutcomeMapper")!=null &&  nodeAttributes.get("jpToOutcomeMapper").isNotNull()) {
				Map<String, Object> keys = nodeAttributes.get("jpToOutcomeMapper").required().asMap();
				Set<String> keySet = keys.keySet();
				for (Iterator<String> i = keySet.iterator(); i.hasNext();) {
					String toSS = i.next();
					outcomes.add(new Outcome(toSS, toSS));
				}
			}

            outcomes.add(new Outcome(NOMATCHRESPONSE, bundle.getString("NoMatchOutcome")));
            outcomes.add(new Outcome(ERROR, bundle.getString("ErrorOutcome")));

            return outcomes;
        }
    }


}