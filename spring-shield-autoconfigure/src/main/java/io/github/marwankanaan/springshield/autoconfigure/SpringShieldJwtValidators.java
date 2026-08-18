package io.github.marwankanaan.springshield.autoconfigure;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;

/**
 * Builds the validator applied to every decoded JWT.
 *
 * <p>
 * Separated from the auto-configuration so the security rules can be tested directly
 * against hand-built tokens, without a decoder, a network call to an identity provider,
 * or a running application context.
 *
 * <p>
 * Every validator here comes from Spring Security. SpringShield decides which ones apply
 * and with what arguments; it does not check signatures, parse tokens, or implement any
 * validation of its own.
 *
 * <p>
 * This class is internal.
 *
 * @author mkanaan
 */
final class SpringShieldJwtValidators {

	private SpringShieldJwtValidators() {
	}

	/**
	 * Creates the validator chain for the configured issuer and audiences.
	 *
	 * <p>
	 * The chain is Spring Security's default set, which covers expiry and not-before,
	 * plus an issuer check, plus an audience check when audiences are configured.
	 * Signature verification is not part of this chain: it happens in the decoder before
	 * any validator runs, so a token with a bad signature never reaches these checks.
	 * @param issuerUri the expected {@code iss} claim, must not be {@code null}
	 * @param audiences accepted {@code aud} values, may be empty to skip the audience
	 * check
	 * @return the validator to install on the decoder
	 */
	static OAuth2TokenValidator<Jwt> create(String issuerUri, List<String> audiences) {
		List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
		validators.add(new JwtIssuerValidator(issuerUri));
		if (!audiences.isEmpty()) {
			validators.add(audienceValidator(audiences));
		}
		return JwtValidators.createDefaultWithValidators(validators);
	}

	/**
	 * Accepts a token whose {@code aud} claim contains at least one configured audience.
	 *
	 * <p>
	 * Spring Security ships {@code JwtAudienceValidator}, but it takes a single audience
	 * and validators are combined with AND. Adding one instance per configured audience
	 * would therefore demand that a token carry <em>every</em> audience at once, which no
	 * issuer produces, and every token would be rejected. The intended meaning is the
	 * opposite: this service may be known by several names, and a token addressed to any
	 * of them is for us.
	 *
	 * <p>
	 * {@code JwtClaimValidator} is Spring Security's supported way to express exactly
	 * that, so the OR is a predicate rather than a validator SpringShield had to write.
	 * @param audiences the accepted audience values, never empty
	 * @return the audience validator
	 */
	private static OAuth2TokenValidator<Jwt> audienceValidator(List<String> audiences) {
		Set<String> accepted = Set.copyOf(audiences);
		return new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
				(tokenAudiences) -> tokenAudiences != null && tokenAudiences.stream().anyMatch(accepted::contains));
	}

}
