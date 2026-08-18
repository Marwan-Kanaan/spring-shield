package io.github.marwankanaan.springshield.autoconfigure;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The rules applied to a decoded JWT.
 *
 * <p>
 * These build tokens directly rather than going through a decoder, so every rule can be
 * checked on its own without a network call to an identity provider and without a running
 * application context. Signature verification is deliberately out of scope here: it
 * happens in the decoder before any of these validators run.
 *
 * @author mkanaan
 */
class SpringShieldJwtValidatorsTests {

	private static final String ISSUER = "https://identity.example.com";

	private static Jwt token(String issuer, List<String> audiences, Instant expiresAt) {
		Jwt.Builder builder = Jwt.withTokenValue("token")
			.header("alg", "RS256")
			.claim("iss", issuer)
			.subject("ada")
			.issuedAt(expiresAt.minus(10, ChronoUnit.MINUTES))
			.expiresAt(expiresAt);
		if (audiences != null) {
			builder.claim("aud", audiences);
		}
		return builder.build();
	}

	private static Jwt validToken() {
		return token(ISSUER, List.of("https://api.example.com"), Instant.now().plus(5, ChronoUnit.MINUTES));
	}

	private static boolean accepts(OAuth2TokenValidator<Jwt> validator, Jwt jwt) {
		return !validator.validate(jwt).hasErrors();
	}

	@Test
	void shouldAcceptATokenFromTheConfiguredIssuer() {
		OAuth2TokenValidator<Jwt> validator = SpringShieldJwtValidators.create(ISSUER, List.of());

		assertThat(accepts(validator, validToken())).isTrue();
	}

	/**
	 * Without this check any issuer able to reach the application could mint tokens it
	 * would accept.
	 */
	@Test
	void shouldRejectATokenFromADifferentIssuer() {
		OAuth2TokenValidator<Jwt> validator = SpringShieldJwtValidators.create(ISSUER, List.of());
		Jwt jwt = token("https://attacker.example.com", List.of("https://api.example.com"),
				Instant.now().plus(5, ChronoUnit.MINUTES));

		assertThat(accepts(validator, jwt)).isFalse();
	}

	@Test
	@DisplayName("issuer comparison is exact, so a lookalike prefix is rejected")
	void shouldRejectAnIssuerThatMerelyStartsWithTheConfiguredValue() {
		OAuth2TokenValidator<Jwt> validator = SpringShieldJwtValidators.create(ISSUER, List.of());
		Jwt jwt = token(ISSUER + ".attacker.com", List.of("https://api.example.com"),
				Instant.now().plus(5, ChronoUnit.MINUTES));

		assertThat(accepts(validator, jwt)).isFalse();
	}

	@Test
	void shouldRejectAnExpiredToken() {
		OAuth2TokenValidator<Jwt> validator = SpringShieldJwtValidators.create(ISSUER, List.of());
		Jwt jwt = token(ISSUER, List.of("https://api.example.com"), Instant.now().minus(1, ChronoUnit.HOURS));

		assertThat(accepts(validator, jwt)).isFalse();
	}

	@Test
	void shouldAcceptATokenWhoseAudienceMatches() {
		OAuth2TokenValidator<Jwt> validator = SpringShieldJwtValidators.create(ISSUER,
				List.of("https://api.example.com"));

		assertThat(accepts(validator, validToken())).isTrue();
	}

	/**
	 * A token minted by the same issuer for a different service must not be usable here.
	 * Without an audience check, every service trusting that issuer would accept every
	 * other service's tokens.
	 */
	@Test
	void shouldRejectATokenIssuedForADifferentService() {
		OAuth2TokenValidator<Jwt> validator = SpringShieldJwtValidators.create(ISSUER,
				List.of("https://api.example.com"));
		Jwt jwt = token(ISSUER, List.of("https://other-service.example.com"),
				Instant.now().plus(5, ChronoUnit.MINUTES));

		assertThat(accepts(validator, jwt)).isFalse();
	}

	/**
	 * The reason a plain list of {@code JwtAudienceValidator} instances is not used: they
	 * combine with AND, so a token would have to carry every configured audience at once.
	 * Configuring several names for this service must accept a token addressed to any one
	 * of them.
	 */
	@Test
	@DisplayName("several configured audiences mean any one of them, not all of them")
	void shouldAcceptATokenMatchingAnyOneOfSeveralConfiguredAudiences() {
		OAuth2TokenValidator<Jwt> validator = SpringShieldJwtValidators.create(ISSUER,
				List.of("https://api.example.com", "https://legacy.example.com"));
		Jwt jwt = token(ISSUER, List.of("https://legacy.example.com"), Instant.now().plus(5, ChronoUnit.MINUTES));

		assertThat(accepts(validator, jwt)).isTrue();
	}

	@Test
	void shouldAcceptATokenCarryingSeveralAudiencesWhenOneMatches() {
		OAuth2TokenValidator<Jwt> validator = SpringShieldJwtValidators.create(ISSUER,
				List.of("https://api.example.com"));
		Jwt jwt = token(ISSUER, List.of("https://other.example.com", "https://api.example.com"),
				Instant.now().plus(5, ChronoUnit.MINUTES));

		assertThat(accepts(validator, jwt)).isTrue();
	}

	@Test
	void shouldRejectATokenWithNoAudienceClaimWhenAudiencesAreConfigured() {
		OAuth2TokenValidator<Jwt> validator = SpringShieldJwtValidators.create(ISSUER,
				List.of("https://api.example.com"));
		Jwt jwt = token(ISSUER, null, Instant.now().plus(5, ChronoUnit.MINUTES));

		assertThat(accepts(validator, jwt)).isFalse();
	}

	/**
	 * Documents the cost of leaving audiences unset: any valid token from the issuer is
	 * accepted, including one minted for another service entirely.
	 */
	@Test
	@DisplayName("with no audiences configured the audience is not checked at all")
	void shouldNotCheckTheAudienceWhenNoneAreConfigured() {
		OAuth2TokenValidator<Jwt> validator = SpringShieldJwtValidators.create(ISSUER, List.of());
		Jwt jwt = token(ISSUER, List.of("https://someone-elses-service.example.com"),
				Instant.now().plus(5, ChronoUnit.MINUTES));

		assertThat(accepts(validator, jwt)).isTrue();
	}

	@Test
	void shouldRejectATokenThatFailsBothIssuerAndAudience() {
		OAuth2TokenValidator<Jwt> validator = SpringShieldJwtValidators.create(ISSUER,
				List.of("https://api.example.com"));
		Jwt jwt = token("https://attacker.example.com", List.of("https://attacker.example.com"),
				Instant.now().plus(5, ChronoUnit.MINUTES));

		assertThat(validator.validate(jwt).getErrors()).isNotEmpty();
	}

}
