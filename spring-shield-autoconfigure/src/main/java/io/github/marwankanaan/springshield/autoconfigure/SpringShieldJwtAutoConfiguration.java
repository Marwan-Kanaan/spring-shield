package io.github.marwankanaan.springshield.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Validates JWT bearer tokens, when the application is configured for them.
 *
 * <p>
 * Active only when {@code springshield.jwt.issuer-uri} is set <em>and</em> Spring
 * Security's OAuth2 resource server support is on the classpath. Add it with:
 *
 * <pre>
 * &lt;dependency&gt;
 *   &lt;groupId&gt;org.springframework.boot&lt;/groupId&gt;
 *   &lt;artifactId&gt;spring-boot-starter-oauth2-resource-server&lt;/artifactId&gt;
 * &lt;/dependency&gt;
 * </pre>
 *
 * <p>
 * There is no separate enable flag. Presence of the issuer is the switch, which makes it
 * impossible to ask for JWT mode without supplying the issuer it needs.
 *
 * <p>
 * This class is internal.
 *
 * <h2>What SpringShield does and does not do</h2>
 *
 * <p>
 * It chooses the decoder and the validators. Everything security-relevant is Spring
 * Security's: signature verification, key handling, expiry, and the issuer and audience
 * checks. SpringShield never parses a token or inspects an unvalidated claim.
 *
 * <h2>Key discovery, startup and rotation</h2>
 *
 * <p>
 * The issuer's metadata is fetched <strong>during startup</strong>, from
 * {@code <issuer-uri>/.well-known/openid-configuration}. That has a consequence worth
 * planning for: if the identity provider is unreachable when the application starts, the
 * application does not start. It is fail-fast rather than fail-open, and a mistyped
 * issuer URI is caught at deployment rather than surfacing later as rejected requests.
 *
 * <p>
 * The cost is a startup dependency on the identity provider. An application that must
 * start during an identity provider outage should declare its own {@code JwtDecoder},
 * built with {@code NimbusJwtDecoder.withJwkSetUri} or from a key it already holds, which
 * skips discovery entirely.
 *
 * <p>
 * Signing keys themselves are fetched from the JWKS endpoint and refreshed as needed
 * after startup, so routine key rotation requires no configuration change and no restart.
 * A token signed with a key the issuer no longer publishes is rejected.
 *
 * @author mkanaan
 */
@AutoConfiguration(after = SpringShieldAutoConfiguration.class)
@ConditionalOnClass({ JwtDecoder.class, NimbusJwtDecoder.class })
@ConditionalOnProperty(prefix = "springshield.jwt", name = "issuer-uri")
@ConditionalOnBean(SpringShieldProperties.class)
public class SpringShieldJwtAutoConfiguration {

	/**
	 * Creates the auto-configuration. Spring calls this; application code should not.
	 */
	public SpringShieldJwtAutoConfiguration() {
	}

	/**
	 * The decoder used to verify and validate incoming bearer tokens.
	 *
	 * <p>
	 * Backs off entirely if the application declares its own {@code JwtDecoder}, which is
	 * the supported way to take over: point it at a fixed JWKS URI, supply a public key
	 * directly, or add validators of your own.
	 *
	 * <p>
	 * Note the order in which a token is checked. The decoder verifies the signature
	 * first, so a forged or tampered token is rejected before any claim is looked at, and
	 * no unverified claim ever reaches an authorization decision.
	 * @param properties the bound {@code springshield} configuration
	 * @return the configured decoder
	 */
	@Bean
	@ConditionalOnMissingBean(JwtDecoder.class)
	JwtDecoder springShieldJwtDecoder(SpringShieldProperties properties) {
		SpringShieldProperties.Jwt jwt = properties.jwt();
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withIssuerLocation(jwt.issuerUri()).build();
		decoder.setJwtValidator(SpringShieldJwtValidators.create(jwt.issuerUri(), jwt.audiences()));
		return decoder;
	}

	/**
	 * Adds bearer token authentication to SpringShield's filter chain.
	 *
	 * <p>
	 * Declared here rather than in the chain itself so the chain still compiles when the
	 * OAuth2 resource server classes are absent. This class carries the
	 * {@link ConditionalOnClass} guard, so the method is only ever loaded when they are
	 * present.
	 *
	 * <p>
	 * Form login and HTTP Basic remain configured alongside it. A JWT application simply
	 * never sends those credentials, and leaving them in place means an application that
	 * uses both is not silently cut off from one of them.
	 *
	 * <p>
	 * Token claims are mapped to authorities here, so a permission in the token matches *
	 * uses both is not silently cut off from one of them.#64;RequiresPermission directly
	 * and a role gains the ROLE_ prefix.
	 * @param properties the bound {@code springshield} configuration
	 * @return the customizer applied to the chain
	 */
	@Bean
	SpringShieldHttpSecurityCustomizer springShieldJwtHttpSecurityCustomizer(SpringShieldProperties properties) {
		SpringShieldProperties.Jwt.ClaimMapping mapping = properties.jwt().claimMapping();
		JwtAuthenticationConverter authenticationConverter = new JwtAuthenticationConverter();
		authenticationConverter.setJwtGrantedAuthoritiesConverter(
				new SpringShieldJwtAuthoritiesConverter(mapping.permissions(), mapping.roles()));
		return (http) -> http.oauth2ResourceServer((resourceServer) -> resourceServer
			.jwt((jwt) -> jwt.jwtAuthenticationConverter(authenticationConverter)));
	}

}
