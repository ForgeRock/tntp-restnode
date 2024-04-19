/*
 * This code is to be used exclusively in connection with Ping Identity Corporation software or services. 
 * Ping Identity Corporation only offers such software or services to legal entities who have entered into 
 * a binding license agreement with Ping Identity Corporation.
 *
 * Copyright 2024 Ping Identity Corporation. All Rights Reserved
 */



package org.forgerock.openam.auth.nodes;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import javax.inject.Inject;

import net.minidev.json.JSONArray;
import org.forgerock.json.JsonValue;
import org.forgerock.json.JsonValueException;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.NodeState;
import org.forgerock.openam.auth.node.api.OutcomeProvider;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.auth.nodes.HttpClientProviderUsingNode.HttpClientConfig;
import org.forgerock.openam.sm.annotations.adapters.Password;
import org.forgerock.openam.sm.annotations.adapters.TextArea;
import org.forgerock.util.i18n.PreferredLocales;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import com.jayway.jsonpath.PathNotFoundException;
import com.sun.identity.sm.RequiredValueValidator;

@Node.Metadata(outcomeProvider = RESTNode.RESTOutcomeProvider.class,
        configClass = RESTNode.Config.class,
        tags            = {"marketplace", "trustnetwork"}
)
public class RESTNode implements Node {

    private final Logger logger = LoggerFactory.getLogger(RESTNode.class);
    private String loggerPrefix = "[RESTNode]" + RESTNodePlugin.logAppender;

    private final Config config;
    private static final String BUNDLE = RESTNode.class.getName();

    private static final String NOMATCHRESPONSE = "NOMATCHRESPONSE";
    private static final String ERROR = "ERROR";

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
        @TextArea
        default String payload() { return ""; }

        @Attribute(order = 55, validators = { RequiredValueValidator.class })
        default BodyType bodyType() {
            return BodyType.JSON;
        }

        @Attribute(order = 600)
    	default TlsVersion protocol() {
    		return TlsVersion.TLS1_3;
    	}

        @Attribute(order = 610)
        default boolean usemTLS() { return false; }

        @Attribute(order = 700)
        default String publicCert() { return "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"; }

        @Attribute(order = 800)
        @Password
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

            HttpClientConfig clientConfig = new HttpClientConfig();
            clientConfig.setTimeout(config.timeout());
            clientConfig.setProtocol(config.protocol().getProtocol());
            clientConfig.setDisableCertChecks(config.disableCertChecks());
            clientConfig.setUsemTLS(config.usemTLS());
            clientConfig.setPublicCert(config.publicCert());
            clientConfig.setPrivateKey(config.privateKey());
            HttpClient httpClient = HttpClientProviderUsingNode.getInstance().getHttpClient(clientConfig);

            // Add request type, payload, timeouts, headers and send
            HttpResponse<String> response = callREST(context, config.requestMode(), httpClient, url, config.headersMap(), config.bodyType(), hydrate(context,config.payload()), config.timeout());

            if (response == null) {
                context.getStateFor(this).putShared("DebugResponse","ERROR");
                return Action.goTo(ERROR).build();
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
            logger.error(loggerPrefix + "Exception occurred: ", ex);
            context.getStateFor(this).putTransient(loggerPrefix + "Exception", ex.getMessage());
            context.getStateFor(this).putTransient(loggerPrefix + "StackTrace", stackTrace);
            return Action.goTo(ERROR).build();
        }

    }


    
    private void processResponse(TreeContext context, String responseBody) {
        NodeState nodeState = context.getStateFor(this);
        Set<String> keys = config.jpToSSMapper().keySet();

        Object document = Configuration.defaultConfiguration().addOptions(Option.SUPPRESS_EXCEPTIONS).jsonProvider().parse(responseBody);

        for (Iterator<String> i = keys.iterator(); i.hasNext();) {
            String toSS = i.next();
            String thisJPath = config.jpToSSMapper().get(toSS);
            try {
                Object val = JsonPath.read(document, thisJPath);
                addToSSOrOA(nodeState, val, toSS);
            } catch (PathNotFoundException e) {
                logger.error(loggerPrefix + " " + e);
            }
        }
    }

    private void addToSSOrOA(NodeState ns, Object val, String toSS) {
    	
        if (val instanceof java.util.LinkedHashMap) {
            JSONObject json = new JSONObject((LinkedHashMap<String, Object>) val);
            val = json.toString();
        } else if (val instanceof net.minidev.json.JSONArray) {
            JSONArray jArray = (JSONArray) val;
            // Convert JSONArray to ArrayList which can be naturally parsed in shared state by Scripted nodes.
            // If array is singleton then return the value, otherwise return the array
            if (jArray.size() == 1) val = jArray.get(0);
            else {
                ArrayList<Object> newArray = new ArrayList<Object>();
                for (int i = 0; i < jArray.size(); i++) {
                    Object item = (Object) jArray.get(i);
                    newArray.add(item);
                }
                val = newArray;
            }
        }
    	
        if (toSS.toLowerCase().startsWith("objectattributes.")) {
        	//then this is a objectAttributes modification
            JsonValue objectAttributes = ns.get("objectAttributes");
            
            if (objectAttributes==null || objectAttributes.isNull()) {
            	objectAttributes = new JsonValue(new LinkedHashMap<String, Object>(1));
            }
            toSS = toSS.replace("objectAttributes.", "");
            objectAttributes.put(toSS, val);
        	ns.putShared("objectattributes", objectAttributes);
        	
        }
        else {
        	ns.putShared(toSS, val);
        }
    	
    	
    }


    /**
     * Try to match response code to user configured outcomes. Supports wildcards such as 2xx, 3xx, etc.
     */
    private String calculateOutcome(List<String>outcomes, int statusCode, TreeContext context, String responseBody)
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
        // This superceeds any previous matching statusCode outcome

        Set<String> keys = config.jpToOutcomeMapper().keySet();

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
     * Call REST endpoint
     */
	private HttpResponse<String> callREST(TreeContext context, RequestMode requestMode, HttpClient httpClient, String url, Map<String, String> headersMap, BodyType bodyType, String payload, int timeout) throws Exception {

		HttpRequest.Builder requestBuilder;

		switch (requestMode) {
		case POST:
			requestBuilder = HttpRequest.newBuilder().POST(HttpRequest.BodyPublishers.ofString(payload));
			break;
		case PUT:
			requestBuilder = HttpRequest.newBuilder().PUT(HttpRequest.BodyPublishers.ofString(payload));
			break;
		case DELETE:
			requestBuilder = HttpRequest.newBuilder().DELETE();
			break;
		case PATCH:
			requestBuilder = HttpRequest.newBuilder().method("PATCH", HttpRequest.BodyPublishers.ofString(payload));
			break;
		case HEAD:
			requestBuilder = HttpRequest.newBuilder().method("HEAD", HttpRequest.BodyPublishers.ofString(payload));
			break;
		case GET:
		default:
			requestBuilder = HttpRequest.newBuilder().GET();
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

		HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
		logger.debug(loggerPrefix + "HttpRequest response: " + response.statusCode());
		logger.debug(loggerPrefix + "HttpRequest response: " + response.body());

		return response;

	}

    /**
     * Populate node outcomes based on configuration options
     */
    public static class RESTOutcomeProvider implements OutcomeProvider {
        @Override
        public List<Outcome> getOutcomes(PreferredLocales locales, JsonValue nodeAttributes) {

            List<Outcome> outcomes = new ArrayList<>();
            ResourceBundle bundle = locales.getBundleInPreferredLocale(BUNDLE, RESTNode.class.getClassLoader());

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

    public enum TlsVersion {
        TLS1_3("TLSv1.3"),
        TLS1_2("TLSv1.2");
    	
    	  private final String protocol;

    	  TlsVersion(String protocol) {
            this.protocol = protocol;
          }

          public String getProtocol() {
            return protocol;
          }
    }

}