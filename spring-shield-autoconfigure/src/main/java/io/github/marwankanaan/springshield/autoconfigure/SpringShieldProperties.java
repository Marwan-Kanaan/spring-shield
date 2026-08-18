package io.github.marwankanaan.springshield.autoconfigure;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Configuration for SpringShield, bound from properties under {@code springshield}.
 *
 * <pre>
 * springshield:
 *   enabled: true
 *   web:
 *     public-endpoints:
 *       - /actuator/health
 *       - /api/public/**
 * </pre>
 *
 * <p>
 * Every value is validated while it binds, so a mistake stops the application from
 * starting rather than becoming an authorization gap discovered later in production. A
 * security setting that is silently ignored is worse than one that fails loudly.
 *
 * <p>
 * Instances are immutable and safe to share between threads.
 *
 * @param enabled Whether SpringShield configures anything at all. When false, the
 * auto-configuration backs off completely and the application keeps Spring Boot's own
 * security defaults, so it stays protected rather than becoming open. Defaults to true.
 * @param web Settings controlling which HTTP requests may be made without authentication.
 * @param authorization Settings for method-level authorization.
 * @param jwt Settings for validating JWT bearer tokens.
 * @author mkanaan
 */
@ConfigurationProperties(prefix = "springshield")
public record SpringShieldProperties(@DefaultValue("true") boolean enabled, @DefaultValue Web web,
		@DefaultValue Authorization authorization, @DefaultValue Jwt jwt) {

	/**
	 * Fills in defaults for any block the application did not supply.
	 */
	public SpringShieldProperties {
		if (web == null) {
			web = new Web(null);
		}
		if (authorization == null) {
			authorization = new Authorization(true);
		}
		if (jwt == null) {
			jwt = new Jwt(null, null, null);
		}
	}

	/**
	 * Settings for method-level authorization.
	 *
	 * @param enabled Whether method security is switched on, which is what makes
	 * &#64;RequiresPermission and &#64;RequiresRole take effect. Defaults to true.
	 * Setting this to false does not relax an existing rule, but it does stop those
	 * annotations being enforced at all, so a method that looks guarded runs unguarded.
	 * @author mkanaan
	 */
	public record Authorization(@DefaultValue("true") boolean enabled) {
	}

	/**
	 * Settings for validating JWT bearer tokens.
	 *
	 * <p>
	 * Setting {@code issuer-uri} is what switches JWT validation on. There is no separate
	 * enable flag, so it is impossible to configure a mode without the issuer it needs.
	 *
	 * @param issuerUri The identity provider that issues the tokens, for example
	 * https://identity.example.com. Its signing keys are discovered from this URI and
	 * refreshed automatically, so key rotation needs no configuration or restart. Tokens
	 * whose iss claim does not match exactly are rejected. Leave unset to disable JWT
	 * validation.
	 * @param audiences Values this service answers to. A token is accepted when its aud
	 * claim contains at least one of them. Empty by default, which means the audience is
	 * not checked at all: any caller holding a valid token from the issuer is accepted,
	 * including one issued for a different service. Set this whenever the issuer serves
	 * more than one application.
	 * @param claimMapping Which token claims carry the caller's roles and permissions.
	 * @author mkanaan
	 */
	public record Jwt(String issuerUri, @DefaultValue List<String> audiences, @DefaultValue ClaimMapping claimMapping) {

		/**
		 * Validates and normalizes the JWT settings.
		 * @throws IllegalArgumentException if the issuer URI is blank or an audience is
		 * blank
		 */
		public Jwt {
			if (issuerUri != null) {
				issuerUri = issuerUri.trim();
				if (issuerUri.isEmpty()) {
					throw new IllegalArgumentException(
							"springshield.jwt.issuer-uri must not be blank. Remove the property to disable JWT "
									+ "validation, or set it to the issuer's URI.");
				}
			}
			audiences = (audiences != null) ? List.copyOf(validateAudiences(audiences)) : List.of();
			if (claimMapping == null) {
				claimMapping = new ClaimMapping("scope", null);
			}
		}

		private static List<String> validateAudiences(List<String> values) {
			List<String> validated = new ArrayList<>(values.size());
			for (String value : values) {
				if (value == null || value.isBlank()) {
					throw new IllegalArgumentException(
							"springshield.jwt.audiences must not contain a blank entry. A blank audience would "
									+ "never match a token and is almost certainly a stray list item.");
				}
				validated.add(value.trim());
			}
			return validated;
		}

		/**
		 * Which token claims carry the caller's roles and permissions.
		 *
		 * <p>
		 * Only claims that survived signature and issuer validation are read, so nothing
		 * here can be influenced by an unverified token.
		 *
		 * @param permissions Claim holding the caller's permissions, mapped to
		 * authorities unchanged so a value of invoice.read satisfies
		 * &#64;RequiresPermission("invoice.read"). Defaults to scope, the standard OAuth2
		 * claim. Accepts either a space-delimited string or a list.
		 * @param roles Claim holding the caller's roles, mapped to authorities with the
		 * ROLE_ prefix Spring Security expects. Unset by default and deliberately so:
		 * there is no standard roles claim, and quietly adopting whatever an issuer
		 * happens to put in a claim called roles or groups could grant roles nobody
		 * configured. Values must be bare names such as ADMIN; a value of ROLE_ADMIN
		 * becomes ROLE_ROLE_ADMIN and matches nothing.
		 * @author mkanaan
		 */
		public record ClaimMapping(@DefaultValue("scope") String permissions, String roles) {

			/**
			 * Validates the claim names.
			 * @throws IllegalArgumentException if either claim name is blank
			 */
			public ClaimMapping {
				permissions = requireClaimName(permissions, "permissions");
				roles = (roles != null) ? requireClaimName(roles, "roles") : null;
			}

			private static String requireClaimName(String value, String name) {
				String trimmed = (value != null) ? value.trim() : "";
				if (trimmed.isEmpty()) {
					throw new IllegalArgumentException(
							("springshield.jwt.claim-mapping.%s must not be blank. Remove the property to use the "
									+ "default, or name the claim to read.")
								.formatted(name));
				}
				return trimmed;
			}

		}

	}

	/**
	 * Settings that control which HTTP requests may be made without authentication.
	 *
	 * @param publicEndpoints Request patterns reachable without authentication, for
	 * example /actuator/health or /api/public/**. Every request that does not match one
	 * of these requires authentication. Patterns must start with '/' and must not expose
	 * the whole application. Defaults to an empty list, so nothing is public until it is
	 * named here.
	 * @author mkanaan
	 */
	public record Web(@DefaultValue List<String> publicEndpoints) {

		/**
		 * Patterns that would expose the entire application.
		 *
		 * <p>
		 * These are rejected rather than accepted. Making every endpoint public is the
		 * single most damaging thing this configuration can express, it is usually added
		 * as a temporary measure during development, and it is easy to leave behind
		 * because nothing afterwards fails or looks wrong. An application that genuinely
		 * wants no authentication should say so by defining its own
		 * {@code SecurityFilterChain}, where the intent is visible in code and shows up
		 * in review.
		 */
		private static final List<String> EXPOSES_EVERYTHING = List.of("/**", "**");

		/**
		 * Validates and normalizes the endpoint patterns.
		 * @throws IllegalArgumentException if any pattern is blank, exposes the whole
		 * application, does not start with {@code /}, or contains whitespace
		 */
		public Web {
			// List.copyOf is applied here rather than inside validate() so the immutable
			// factory is visible at the assignment. Static analysis cannot otherwise see
			// that the accessor never exposes a mutable list. It costs nothing: copyOf
			// returns its argument unchanged when it is already immutable.
			publicEndpoints = (publicEndpoints != null) ? List.copyOf(validate(publicEndpoints)) : List.of();
		}

		private static List<String> validate(List<String> patterns) {
			List<String> validated = new ArrayList<>(patterns.size());
			for (String pattern : patterns) {
				validated.add(validatePattern(pattern));
			}
			return validated;
		}

		private static String validatePattern(String pattern) {
			if (pattern == null || pattern.isBlank()) {
				throw new IllegalArgumentException("springshield.web.public-endpoints must not contain a blank entry. "
						+ "Remove the empty list item, or delete the property if nothing should be public.");
			}
			String trimmed = pattern.trim();
			if (EXPOSES_EVERYTHING.contains(trimmed)) {
				throw new IllegalArgumentException(
						("springshield.web.public-endpoints must not contain '%s', because that makes every endpoint "
								+ "in the application reachable without authentication. List the specific paths that "
								+ "should be public, or define your own SecurityFilterChain bean if the application "
								+ "genuinely needs no authentication.")
							.formatted(trimmed));
			}
			if (!trimmed.startsWith("/")) {
				throw new IllegalArgumentException(
						("springshield.web.public-endpoints entries must start with '/', but was '%s'. "
								+ "A pattern that does not start with '/' never matches a request path, so the "
								+ "endpoint would silently stay protected.")
							.formatted(trimmed));
			}
			for (int i = 0; i < trimmed.length(); i++) {
				if (Character.isWhitespace(trimmed.charAt(i))) {
					throw new IllegalArgumentException(
							("springshield.web.public-endpoints entries must not contain whitespace, but was '%s'. "
									+ "This is usually a missing list separator, which would leave the intended "
									+ "path protected.")
								.formatted(trimmed));
				}
			}
			return trimmed;
		}

	}

}
