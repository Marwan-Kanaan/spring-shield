package io.github.marwankanaan.springshield.autoconfigure;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import io.github.marwankanaan.springshield.RequiresPermission;
import io.github.marwankanaan.springshield.RequiresRole;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The whole JWT path, end to end, with real signed tokens.
 *
 * <p>
 * A stub issuer publishes a key set, tokens are signed with the matching private key, and
 * they travel as bearer tokens through the real filter chain. This is the only test that
 * proves the parts fit together: decoding, signature verification, issuer and audience
 * validation, claim mapping, and the annotations authorizing against the resulting
 * authorities.
 *
 * @author mkanaan
 */
@SpringBootTest(classes = { JwtEndToEndIntegrationTests.TestApplication.class,
		JwtEndToEndIntegrationTests.InvoiceController.class })
@AutoConfigureMockMvc
class JwtEndToEndIntegrationTests {

	private static StubIssuer issuer;

	private static JwtEncoder encoder;

	@Autowired
	private MockMvc mvc;

	@BeforeAll
	static void startIssuer() throws Exception {
		issuer = StubIssuer.start();
		encoder = encoderFor(issuer);
	}

	@AfterAll
	static void stopIssuer() {
		issuer.close();
	}

	@DynamicPropertySource
	static void springShieldProperties(DynamicPropertyRegistry registry) {
		registry.add("springshield.jwt.issuer-uri", () -> issuer.issuerUri());
		registry.add("springshield.jwt.audiences[0]", () -> "https://api.example.com");
		registry.add("springshield.jwt.claim-mapping.roles", () -> "roles");
	}

	private static JwtEncoder encoderFor(StubIssuer stub) {
		return NimbusJwtEncoder
			.withKeyPair((RSAPublicKey) stub.keyPair().getPublic(), (RSAPrivateKey) stub.keyPair().getPrivate())
			.jwkPostProcessor((jwk) -> jwk.keyID(StubIssuer.KEY_ID))
			.build();
	}

	private static String sign(JwtEncoder with, JwtClaimsSet claims) {
		return with.encode(JwtEncoderParameters.from(JwsHeader.with(() -> "RS256").build(), claims)).getTokenValue();
	}

	private static JwtClaimsSet.Builder claims(String audience) {
		return JwtClaimsSet.builder()
			.issuer(issuer.issuerUri())
			.subject("ada")
			.audience(List.of(audience))
			.issuedAt(Instant.now())
			.expiresAt(Instant.now().plus(5, ChronoUnit.MINUTES));
	}

	private static String tokenWith(String scope, List<String> roles, String audience) {
		JwtClaimsSet.Builder builder = claims(audience);
		if (scope != null) {
			builder.claim("scope", scope);
		}
		if (roles != null) {
			builder.claim("roles", roles);
		}
		return sign(encoder, builder.build());
	}

	private static String validToken() {
		return tokenWith("invoice.read", List.of("ADMIN"), "https://api.example.com");
	}

	@Test
	@DisplayName("a permission in the token satisfies @RequiresPermission")
	void shouldAllowAccessWhenTheTokenCarriesTheRequiredPermission() throws Exception {
		this.mvc.perform(get("/api/invoices").header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken()))
			.andExpect(status().isOk());
	}

	@Test
	@DisplayName("a role in the token satisfies @RequiresRole")
	void shouldAllowAccessWhenTheTokenCarriesTheRequiredRole() throws Exception {
		this.mvc.perform(get("/api/invoices/admin").header(HttpHeaders.AUTHORIZATION, "Bearer " + validToken()))
			.andExpect(status().isOk());
	}

	/**
	 * Authenticated is not authorized. A perfectly valid token still cannot reach an
	 * endpoint whose permission it does not carry.
	 */
	@Test
	void shouldDenyAValidTokenThatLacksTheRequiredPermission() throws Exception {
		String token = tokenWith("invoice.list", List.of("ADMIN"), "https://api.example.com");

		this.mvc.perform(get("/api/invoices").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
			.andExpect(status().isForbidden())
			.andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
	}

	@Test
	void shouldDenyAValidTokenThatLacksTheRequiredRole() throws Exception {
		String token = tokenWith("invoice.read", List.of("AUDITOR"), "https://api.example.com");

		this.mvc.perform(get("/api/invoices/admin").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
			.andExpect(status().isForbidden());
	}

	@Test
	void shouldRejectARequestWithNoToken() throws Exception {
		this.mvc.perform(get("/api/invoices"))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
	}

	/**
	 * The signature check is the foundation everything else rests on. A token signed with
	 * a key the issuer does not publish must be rejected before any claim is read.
	 */
	@Test
	@DisplayName("a token signed with a key the issuer does not publish is rejected")
	void shouldRejectATokenSignedByAnotherKey() throws Exception {
		try (StubIssuer other = StubIssuer.start()) {
			String forged = sign(encoderFor(other),
					claims("https://api.example.com").claim("scope", "invoice.read").build());

			this.mvc.perform(get("/api/invoices").header(HttpHeaders.AUTHORIZATION, "Bearer " + forged))
				.andExpect(status().isUnauthorized());
		}
	}

	@Test
	void shouldRejectAnExpiredToken() throws Exception {
		String expired = sign(encoder,
				JwtClaimsSet.builder()
					.issuer(issuer.issuerUri())
					.subject("ada")
					.audience(List.of("https://api.example.com"))
					.issuedAt(Instant.now().minus(2, ChronoUnit.HOURS))
					.expiresAt(Instant.now().minus(1, ChronoUnit.HOURS))
					.claim("scope", "invoice.read")
					.build());

		this.mvc.perform(get("/api/invoices").header(HttpHeaders.AUTHORIZATION, "Bearer " + expired))
			.andExpect(status().isUnauthorized());
	}

	/**
	 * A token the same issuer minted for another service must not be usable here.
	 */
	@Test
	void shouldRejectATokenIssuedForADifferentAudience() throws Exception {
		String token = tokenWith("invoice.read", List.of("ADMIN"), "https://other-service.example.com");

		this.mvc.perform(get("/api/invoices").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
			.andExpect(status().isUnauthorized());
	}

	@Test
	void shouldRejectAMalformedToken() throws Exception {
		this.mvc.perform(get("/api/invoices").header(HttpHeaders.AUTHORIZATION, "Bearer not-a-jwt"))
			.andExpect(status().isUnauthorized());
	}

	/**
	 * Application under test.
	 *
	 * @author mkanaan
	 */
	@SpringBootApplication
	static class TestApplication {

	}

	/**
	 * Endpoints guarded by a permission and by a role.
	 *
	 * @author mkanaan
	 */
	@RestController
	static class InvoiceController {

		@GetMapping("/api/invoices")
		@RequiresPermission("invoice.read")
		String invoices() {
			return "invoices";
		}

		@GetMapping("/api/invoices/admin")
		@RequiresRole("ADMIN")
		String adminView() {
			return "admin";
		}

	}

}
