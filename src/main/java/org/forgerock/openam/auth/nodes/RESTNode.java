/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2023 ForgeRock AS.
 */
/**
 * jon.knight@forgerock.com
 *
 * An authentication node to generate REST API calls
 */


package org.forgerock.openam.auth.nodes;

import com.google.inject.assistedinject.Assisted;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.*;
import org.forgerock.util.i18n.PreferredLocales;
import static org.forgerock.openam.auth.node.api.Action.send;
import org.forgerock.openam.utils.JsonValueBuilder;
import org.forgerock.openam.sm.annotations.adapters.Password;

import javax.mail.NoSuchProviderException;
import javax.security.auth.callback.Callback;

import java.util.Optional;
import java.util.Map;
import java.util.Iterator;
import java.util.List;
import java.util.Base64;
import java.util.Collections;
import java.util.Collection;
import java.util.Set;
import java.util.ResourceBundle;
import static java.util.Collections.emptyList;
import java.util.stream.Collectors;
import com.google.common.collect.ImmutableList;
import javax.inject.Inject;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.UnrecoverableKeyException;
import java.security.KeyManagementException;
import java.security.SecureRandom;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.SSLEngine;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.net.Socket;

import java.lang.InterruptedException;
import java.time.Duration;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import com.jayway.jsonpath.PathNotFoundException;

/**
 * A node that executes a client-side Javascript and stores any resulting output in the shared state.
 */

@Node.Metadata(outcomeProvider = RESTNode.RESTOutcomeProvider.class,
        configClass = RESTNode.Config.class)
public class RESTNode implements Node {

    private final Logger logger = LoggerFactory.getLogger(RESTNode.class);
    private String loggerPrefix = "[RESTNode]" + RESTNodePlugin.logAppender;

    private final Config config;
    private static final String BUNDLE = RESTNode.class.getName();


    public enum RequestMode {
        GET, POST, PUT, DELETE, PATCH, HEAD
    }

    public enum BodyType {
        XWWWFORMURLENCODED, JSON, XML, PLAIN
    }

    /**
     * Configuration for the node.
     */

    public interface Config {
        @Attribute(order = 100)
        default String restURL() { return ""; }

        @Attribute(order = 200)
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

        @Attribute(order = 500)
        default String payload() { return ""; }

        @Attribute(order = 550)
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
    }


    /**
     * Guice constructor.
     * @param config The node configuration.
     * @throws NodeProcessException If there is an error reading the configuration.
     */
    @Inject
    public RESTNode(@Assisted Config config) throws NodeProcessException {
        this.config = config;
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        try {
            logger.debug(loggerPrefix + "Started");

            // Construct URL with query parameters including variable substitution from sharedState
            String url = hydrate(context,(config.restURL() + getQueryString(context, config.queryParamsMap())));
            logger.debug(loggerPrefix + "Final URL: " + url);

            // Create httpClient including mTLS certs and certificate checking if requested
            HttpClient httpClient = getmTLShttpClient(config);

            // Add request type, payload, timeouts, headers and send
            HttpResponse response = callREST(context, config.requestMode(), httpClient, url, config.headersMap(), config.bodyType(), hydrate(context,config.payload()), config.timeout());

            if (response == null) {
                context.getStateFor(this).putShared("DebugResponse","ERROR");
                return Action.goTo("Error").build();
            } else {
                if ((config.statusCodeReturn() != null) && (config.statusCodeReturn() != "")) context.getStateFor(this).putShared(config.statusCodeReturn(),response.statusCode());
                if ((config.bodyReturn() != null) && (config.bodyReturn() != "")) context.getStateFor(this).putShared(config.bodyReturn(),response.body());
                processResponse(context, response.body().toString());

                // Choose dynamic outcome if provided in config, e.g., response code 200, 401, etc
                String outcome = calculateOutcome(config.responseCodes(), response.statusCode(), context, response.body().toString());

                return Action.goTo(outcome).build();
            }

        } catch (Exception ex) {
            String stackTrace = org.apache.commons.lang.exception.ExceptionUtils.getStackTrace(ex);
            logger.error(loggerPrefix + "Exception occurred: " + stackTrace);
            context.getStateFor(this).putShared(loggerPrefix + "Exception", ex.getMessage());
            context.getStateFor(this).putShared(loggerPrefix + "StackTrace", stackTrace);
            return Action.goTo("error").build();
        }

    }


    public void processResponse(TreeContext context, String responseBody) {
        NodeState nodeState = context.getStateFor(this);
        Set<String> keys = config.jpToSSMapper().keySet();

        Object document = Configuration.defaultConfiguration().addOptions(Option.SUPPRESS_EXCEPTIONS).jsonProvider().parse(responseBody);

        for (Iterator<String> i = keys.iterator(); i.hasNext();) {
            String toSS = i.next();
            String thisJPath = config.jpToSSMapper().get(toSS);
            try {
                Object val = JsonPath.read(document, thisJPath);
                nodeState.putShared(toSS, val);
            } catch (PathNotFoundException e) {
                logger.error(loggerPrefix + " " + e);
            }
        }
    }



    /**
     * Try to match response code to user configured outcomes. Supports wildcards such as 2xx, 3xx, etc.
     */
    public String calculateOutcome(List<String>outcomes, int statusCode, TreeContext context, String responseBody)
    {
        String result = "Success";
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
        // This superceeds any previous matching statusCode outcome
        NodeState nodeState = context.getStateFor(this);
        Set<String> keys = config.jpToOutcomeMapper().keySet();

        responseBody = '[' + responseBody + ']'; // JSONpath expressions/filters only apply to arrays, so top-level JSON needs to be wrapped in an array
        Object document = Configuration.defaultConfiguration().addOptions(Option.SUPPRESS_EXCEPTIONS).jsonProvider().parse(responseBody);

        for (Iterator<String> i = keys.iterator(); i.hasNext();) {
            String toSS = i.next();
            String thisJPath = config.jpToOutcomeMapper().get(toSS);
            List<String> vals = JsonPath.read(document, thisJPath);
            if (vals.size() > 0) {
                result = toSS;
                break;  // Exit at first matching outcome
            }
        }

        return result;
    }

    /**
     * Convert query string map to URL encoded query string
     */
    public String getQueryString(TreeContext context, Map<String, String> queryMap)
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
     * Process string to replace placeholder variables {{likethis}} with values from sharedState
     * Values of the form {{variable.$.<jsonpath>}} will be retrieved from shared state, and processed by JSONpath
     */
    public String hydrate(TreeContext context, String source) {
        try {
            if (source != null) {
                String target = "";
                Boolean scanning = true;
                while (scanning) {
                    int start = source.indexOf("{{");
                    int end = source.indexOf("}}");
                    if ((start != -1) && (end != -1)) {
                        target = target + source.substring(0, start);
                        String variable = source.substring(start + 2, end);

                        if (variable.indexOf(".$.") > 0) {  // Use JSONpath substitution
                            JsonValue thisJV = context.sharedState.get(variable.substring(0, variable.indexOf('.')));

                            // If shared state value is stringified JSON then unescape it so it can be parsed
                            String thisJVStr;
                            if (thisJV.isString()) thisJVStr = thisJV.asString().replace("\\\"","");
                            else thisJVStr = thisJV.toString();

                            Object document = Configuration.defaultConfiguration().addOptions(Option.SUPPRESS_EXCEPTIONS).jsonProvider().parse(thisJVStr);

                            // Ignore (nullify) invalid JSON content
                            try {
                                Object val = JsonPath.read(document, variable.substring(variable.indexOf('.') + 1, variable.length()));
                                target += val;
                            } catch (PathNotFoundException e) {
                                logger.error(loggerPrefix + " " + e);
                                target += "null";
                            }

                        } else { // Use simple string substitution
                            JsonValue json = context.sharedState.get(variable);
                            if (json.isString()) target += context.sharedState.get(variable).asString().replace("\\\"","");
                            else target += context.sharedState.get(variable).toString();
                        }

                        source = source.substring(end + 2, source.length());
                    } else {
                        target = target + source;
                        scanning = false;
                    }
                }
                return target;
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


    public static String getRandomString() {
        byte[] bytes = new byte[24];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * Create httpClient with suitable config for mTLS, certs, ignore certs, etc.
     */
    public HttpClient getmTLShttpClient(Config config) {

        KeyManager[] keyManager = null;
        TrustManager[] trustManager = null;
        SSLParameters sslParam = new SSLParameters();

        // parse certificate
        try {
            if (config.usemTLS()) {

                final byte[] publicData = config.publicCert().replaceAll(" ","\n").replaceAll("\nCERTIFICATE"," CERTIFICATE").getBytes();
                final byte[] privateData = Base64.getDecoder().decode(config.privateKey().replaceAll("-----BEGIN PRIVATE KEY-----", "").replaceAll("-----END PRIVATE KEY-----", "").replaceAll("\\s", ""));

                final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                final Collection<? extends Certificate> chain = certificateFactory.generateCertificates(
                    new ByteArrayInputStream(publicData));

                logger.debug(loggerPrefix + "Successfully loaded the client cert certificate chain: " + String.join(" -> ", chain
                    .stream()
                    .map(certificate -> {
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
                trustManager = new TrustManager[]{insecureTrustManager};
            }

            // populate SSLContext with key manager
            SSLContext sslCtx = SSLContext.getInstance("TLSv1.2");
            sslCtx.init(keyManager, trustManager, null);

            HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(config.timeout()))
                .sslContext(sslCtx)
                .sslParameters(sslParam)
                .build();

            return client;
        } catch (KeyManagementException | UnrecoverableKeyException | KeyStoreException | IOException | InvalidKeySpecException | NoSuchAlgorithmException | CertificateException e) {
            logger.error(loggerPrefix + "Exception occurred: " + e);
            return null;
        }          
    }

    /**
     * Call REST endpoint
     */
    public HttpResponse callREST(TreeContext context, RequestMode requestMode, HttpClient httpClient, String url, Map<String,String> headersMap, BodyType bodyType, String payload, int timeout) {
        try {

            String contentType;
            HttpRequest.Builder requestBuilder;

            switch(requestMode) {
                case POST:
                    requestBuilder = HttpRequest.newBuilder()
                        .POST(HttpRequest.BodyPublishers.ofString(payload));
                    break; 
                case PUT:
                    requestBuilder = HttpRequest.newBuilder()
                        .PUT(HttpRequest.BodyPublishers.ofString(payload));
                    break; 
                case DELETE:
                    requestBuilder = HttpRequest.newBuilder()
                        .DELETE();
                    break; 
                case PATCH:
                    requestBuilder = HttpRequest.newBuilder()
                        .method("PATCH", HttpRequest.BodyPublishers.ofString(payload));
                    break; 
                case HEAD:
                    requestBuilder = HttpRequest.newBuilder()
                        .method("HEAD", HttpRequest.BodyPublishers.ofString(payload));
                    break;                     
                case GET:
                default:
                    requestBuilder = HttpRequest.newBuilder()
                        .GET();
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
                    requestBuilder.header("content-type", "application/xml");
                    break;
                case PLAIN:
                default:
                    requestBuilder.header("content-type", "text/plain");
                    break;
            }

            for (Map.Entry<String, String> entry : headersMap.entrySet()) {
                requestBuilder.header(entry.getKey(),hydrate(context, entry.getValue()));
            }

            HttpRequest request = requestBuilder
                                    .uri(URI.create(url))
                                    .timeout(Duration.ofSeconds(timeout))
                                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            logger.debug(loggerPrefix + "HttpRequest response: " + response.statusCode());
            logger.debug(loggerPrefix + "HttpRequest response: " + response.body());

            return response;
        } catch (InterruptedException | IOException e) {
            logger.error(loggerPrefix + "Exception occurred: " + e);
            return null;
        }        
    }

    /**
     * Populate node outcomes based on configuration options
     */
    public static class RESTOutcomeProvider implements OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {

            List<Outcome> outcomes;

            try {
                outcomes = nodeAttributes.get("responseCodes").required()
                        .asList(String.class)
                        .stream()
                        .map(choice -> new Outcome(choice, choice))
                        .collect(Collectors.toList());
            } catch (JsonValueException e) {
                outcomes = emptyList();
            }

            if (outcomes == null) outcomes = emptyList();

            Map<String,Object> keys = nodeAttributes.get("jpToOutcomeMapper").required().asMap();
            Set<String> keySet = keys.keySet();
            for (Iterator<String> i = keySet.iterator(); i.hasNext();) {
                String toSS = i.next();
                outcomes.add(new Outcome(toSS, toSS));
            }

            outcomes.add(new Outcome("Success","Success"));
            outcomes.add(new Outcome("Error","Error"));

            return outcomes;
        }
    }


}

