package org.forgerock.openam.auth.nodes;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.Socket;
import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Collection;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.stream.Collectors;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

public class HttpClientProviderUsingNode {
	
    private final Logger logger = LoggerFactory.getLogger(HttpClientProviderUsingNode.class);
	
	private static HttpClientProviderUsingNode INSTANCE;
	
	private final LoadingCache<HttpClientConfig, HttpClient> httpClientCache;


	
	public static synchronized HttpClientProviderUsingNode getInstance() {
		if (INSTANCE == null) {
			INSTANCE = new HttpClientProviderUsingNode();
		}
		return INSTANCE;
	}
	

	private HttpClientProviderUsingNode() {
		this.httpClientCache = CacheBuilder.newBuilder().build(new CacheLoader<>() {
			@Override
			public HttpClient load(HttpClientConfig config) throws Exception {
				logger.debug("Creating new client for: " + config);
				HttpClient.Builder builder = HttpClient.newBuilder(); 
				addSslSettings(config, builder);
				return builder.connectTimeout(Duration.ofSeconds(config.timeout)).build();
				
			}
		});

	}
	
	public HttpClient getHttpClient(HttpClientConfig config) throws ExecutionException {
		return httpClientCache.get(config);
	}

	
	private void addSslSettings(HttpClientConfig config, HttpClient.Builder builder) throws GeneralSecurityException, IOException {
		KeyManager[] keyManager = null;
		TrustManager[] trustManager = null;
		SSLParameters sslParam = new SSLParameters();
		if (config.usemTLS) {
			keyManager = buildKeyManager(config);
			sslParam.setNeedClientAuth(true);
		}

		if (config.disableCertChecks) {
			trustManager = new TrustManager[] { TRUST_ALL_MANAGER };
		}

		// populate SSLContext with key manager
		SSLContext sslCtx = SSLContext.getInstance(config.protocol);
		sslCtx.init(keyManager, trustManager, null);
		builder.sslContext(sslCtx).sslParameters(sslParam); 

	}


	private KeyManager[] buildKeyManager(HttpClientConfig config) throws GeneralSecurityException,IOException {
		KeyManager[] keyManager;
		final char[] pwdChars = getRandomString().toCharArray();
		final byte[] publicData = config.publicCert.replaceAll(" ", "\n").replaceAll("\nCERTIFICATE", " CERTIFICATE").getBytes();
		final byte[] privateData = Base64.getDecoder().decode(config.privateKey.replaceAll("-----BEGIN PRIVATE KEY-----", "").replaceAll("-----END PRIVATE KEY-----", "").replaceAll("\\s", ""));

		final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		final Collection<? extends Certificate> chain = certificateFactory.generateCertificates(new ByteArrayInputStream(publicData));

		logger.debug("Successfully loaded the client cert certificate chain: " + String.join(" -> ", chain.stream().map(certificate -> {
			if (certificate instanceof X509Certificate) {
				final X509Certificate x509Cert = (X509Certificate) certificate;
				return x509Cert.getSubjectX500Principal().toString();
			} else {
				return certificate.getType();
			}
		}).collect(Collectors.toList())));

		final Key rsaKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateData));

		// place cert+key into KeyStore
		KeyStore clientKeyStore;
		clientKeyStore = KeyStore.getInstance("jks"); 

		clientKeyStore.load(null, null);
		clientKeyStore.setKeyEntry("mtls-cert", rsaKey, pwdChars, chain.toArray(new Certificate[0]));

		// initialize KeyManagerFactory
		KeyManagerFactory keyMgrFactory = KeyManagerFactory.getInstance("SunX509");
		keyMgrFactory.init(clientKeyStore, pwdChars);
		keyManager = keyMgrFactory.getKeyManagers();
		return keyManager;
	}
	

    private static String getRandomString() {
        byte[] bytes = new byte[24];
        SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
	
	
    /**
     * Implementation of a certificate trustmanager to ignore invalid cert problems (wrong host, expired, etc)
     */
    private static final TrustManager TRUST_ALL_MANAGER = new X509ExtendedTrustManager() {
        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[0];
        }
        @Override
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) { }
        @Override
        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType)  { }
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) { }
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)  { }
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)  { }
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) { }
    };

    public static class HttpClientConfig {

	  		private String protocol;
			private int timeout;
	  		private boolean usemTLS;
	  		private String publicCert;
			private String privateKey;
			private boolean disableCertChecks;
			
			public HttpClientConfig() {

			}

			public void setProtocol(String protocol) {
				this.protocol = protocol;
			}

			public void setTimeout(int timeout) {
				this.timeout = timeout;
			}

			public void setUsemTLS(boolean usemTLS) {
				this.usemTLS = usemTLS;
			}

			public void setPublicCert(String publicCert) {
				this.publicCert = publicCert;
			}

			public void setPrivateKey(String privateKey) {
				this.privateKey = privateKey;
			}

			public void setDisableCertChecks(boolean disableCertChecks) {
				this.disableCertChecks = disableCertChecks;
			}

			@Override
			public int hashCode() {
				return Objects.hash(disableCertChecks, timeout, usemTLS, protocol, privateKey, publicCert);
			}

			@Override
			public boolean equals(Object obj) {
				if (this == obj)
					return true;
				if (obj == null)
					return false;
				if (getClass() != obj.getClass())
					return false;
				HttpClientConfig other = (HttpClientConfig) obj;
				return 	disableCertChecks == other.disableCertChecks
						&& timeout == other.timeout
						&& usemTLS == other.usemTLS
						&& Objects.equals(protocol, other.protocol)
						&& Objects.equals(privateKey, other.privateKey) 
						&& Objects.equals(publicCert, other.publicCert);
			}

			@Override
			public String toString() {
				return "HttpClientConfig [protocol=" + protocol + ", timeout=" + timeout + ", usemTLS=" + usemTLS
						+ ", disableCertChecks=" + disableCertChecks + "]";
			}

			
    }

}
