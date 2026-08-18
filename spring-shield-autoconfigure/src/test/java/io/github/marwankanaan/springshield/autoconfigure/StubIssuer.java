package io.github.marwankanaan.springshield.autoconfigure;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * A minimal stand-in for an OpenID Connect identity provider.
 *
 * <p>
 * SpringShield's decoder fetches the issuer's metadata during startup, so a test that
 * builds one needs something to answer that request. This serves just enough of a
 * discovery document to satisfy it.
 *
 * <p>
 * Uses the JDK's own HTTP server, so the tests need no extra dependency and no real
 * network: it listens on loopback on an ephemeral port, which keeps runs independent of
 * each other and safe to run in parallel.
 *
 * @author mkanaan
 */
final class StubIssuer implements AutoCloseable {

	private final HttpServer server;

	private final String issuerUri;

	private final KeyPair keyPair;

	/**
	 * Returns the key pair whose public half this issuer publishes.
	 *
	 * <p>
	 * The private half is available so a test can sign a token this issuer would vouch
	 * for.
	 * @return the key pair
	 */
	KeyPair keyPair() {
		return this.keyPair;
	}

	/**
	 * Renders the public key as a JWK set.
	 *
	 * <p>
	 * A key set with no keys is not enough: the decoder inspects the published keys
	 * during startup to work out which signing algorithms the issuer supports, and
	 * rejects a set it cannot derive any from.
	 * @param publicKey the key to publish
	 * @return the JWK set document
	 */
	private static String jwks(RSAPublicKey publicKey) {
		return """
				{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"stub","n":"%s","e":"%s"}]}"""
			.formatted(base64Url(publicKey.getModulus()), base64Url(publicKey.getPublicExponent()));
	}

	/**
	 * Encodes a positive integer the way JWK requires: unsigned big-endian, base64url, no
	 * padding.
	 *
	 * <p>
	 * {@link BigInteger#toByteArray()} prefixes a zero byte when the top bit is set, to
	 * keep the value positive in two's complement. That byte is not part of the number
	 * and must be dropped, or the modulus decodes to a different key.
	 * @param value the value to encode
	 * @return the base64url encoding
	 */
	private static String base64Url(BigInteger value) {
		byte[] bytes = value.toByteArray();
		if (bytes.length > 1 && bytes[0] == 0) {
			byte[] trimmed = new byte[bytes.length - 1];
			System.arraycopy(bytes, 1, trimmed, 0, trimmed.length);
			bytes = trimmed;
		}
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	private StubIssuer(HttpServer server, String issuerUri, KeyPair keyPair) {
		this.server = server;
		this.issuerUri = issuerUri;
		this.keyPair = keyPair;
	}

	/**
	 * Starts a stub issuer on a free loopback port.
	 * @return the running stub, to be closed by the caller
	 * @throws IOException if the server cannot be started
	 */
	static StubIssuer start() throws IOException, NoSuchAlgorithmException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		KeyPair keyPair = generator.generateKeyPair();
		HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		String issuerUri = "http://127.0.0.1:" + server.getAddress().getPort();
		// The metadata must echo the issuer back unchanged. Spring Security compares the
		// two
		// and rejects a provider that claims a different identity than the one asked for,
		// which is what stops a redirected discovery request substituting another issuer.
		String metadata = """
				{"issuer":"%s","jwks_uri":"%s/jwks","response_types_supported":["code"],\
				"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"],\
				"authorization_endpoint":"%s/authorize","token_endpoint":"%s/token"}""".formatted(issuerUri, issuerUri,
				issuerUri, issuerUri);
		server.createContext("/.well-known/openid-configuration", (exchange) -> respond(exchange, metadata));
		String jwks = jwks((RSAPublicKey) keyPair.getPublic());
		server.createContext("/jwks", (exchange) -> respond(exchange, jwks));
		server.start();
		return new StubIssuer(server, issuerUri, keyPair);
	}

	private static void respond(HttpExchange exchange, String body) throws IOException {
		byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
		exchange.getResponseHeaders().add("Content-Type", "application/json");
		exchange.sendResponseHeaders(200, bytes.length);
		try (OutputStream out = exchange.getResponseBody()) {
			out.write(bytes);
		}
	}

	/**
	 * Returns the issuer URI to configure SpringShield with.
	 * @return the issuer URI
	 */
	String issuerUri() {
		return this.issuerUri;
	}

	@Override
	public void close() {
		this.server.stop(0);
	}

}
