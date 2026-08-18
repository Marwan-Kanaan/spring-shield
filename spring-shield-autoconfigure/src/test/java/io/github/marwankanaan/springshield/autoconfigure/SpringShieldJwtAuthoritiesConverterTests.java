package io.github.marwankanaan.springshield.autoconfigure;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Claim-to-authority mapping.
 *
 * <p>
 * These decide whether a bearer token can satisfy {@code @RequiresPermission} and
 * {@code @RequiresRole}, so they check the exact authority strings produced rather than
 * just that something was produced.
 *
 * @author mkanaan
 */
class SpringShieldJwtAuthoritiesConverterTests {

	private static Jwt token(String claim, Object value) {
		return Jwt.withTokenValue("token")
			.header("alg", "RS256")
			.subject("ada")
			.issuedAt(Instant.now())
			.expiresAt(Instant.now().plus(5, ChronoUnit.MINUTES))
			.claim(claim, value)
			.build();
	}

	private static List<String> authorities(SpringShieldJwtAuthoritiesConverter converter, Jwt jwt) {
		return converter.convert(jwt).stream().map(GrantedAuthority::getAuthority).toList();
	}

	@Test
	@DisplayName("a permission is used verbatim, so it matches @RequiresPermission directly")
	void shouldMapPermissionsWithoutAPrefix() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", null);

		assertThat(authorities(converter, token("scope", "invoice.read"))).containsExactly("invoice.read");
	}

	@Test
	@DisplayName("the standard scope claim may be a space-delimited string")
	void shouldSplitASpaceDelimitedScopeClaim() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", null);

		assertThat(authorities(converter, token("scope", "invoice.read invoice.export")))
			.containsExactlyInAnyOrder("invoice.read", "invoice.export");
	}

	@Test
	void shouldReadAPermissionsClaimGivenAsAList() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("permissions", null);

		assertThat(authorities(converter, token("permissions", List.of("invoice.read", "invoice.export"))))
			.containsExactlyInAnyOrder("invoice.read", "invoice.export");
	}

	@Test
	@DisplayName("a role gains the ROLE_ prefix Spring Security expects")
	void shouldMapRolesWithTheRolePrefix() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", "roles");

		assertThat(authorities(converter, token("roles", List.of("ADMIN")))).containsExactly("ROLE_ADMIN");
	}

	@Test
	void shouldCombinePermissionsAndRolesFromSeparateClaims() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", "roles");
		Jwt jwt = Jwt.withTokenValue("token")
			.header("alg", "RS256")
			.subject("ada")
			.issuedAt(Instant.now())
			.expiresAt(Instant.now().plus(5, ChronoUnit.MINUTES))
			.claim("scope", "invoice.read")
			.claim("roles", List.of("ADMIN"))
			.build();

		assertThat(authorities(converter, jwt)).containsExactlyInAnyOrder("invoice.read", "ROLE_ADMIN");
	}

	/**
	 * Roles are read only when a claim is named. Adopting a claim called {@code roles}
	 * that nobody configured could hand out roles the application never intended to
	 * recognise.
	 */
	@Test
	void shouldIgnoreARolesClaimWhenNoRolesClaimIsConfigured() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", null);
		Jwt jwt = Jwt.withTokenValue("token")
			.header("alg", "RS256")
			.subject("ada")
			.issuedAt(Instant.now())
			.expiresAt(Instant.now().plus(5, ChronoUnit.MINUTES))
			.claim("scope", "invoice.read")
			.claim("roles", List.of("ADMIN"))
			.build();

		assertThat(authorities(converter, jwt)).containsExactly("invoice.read");
	}

	/**
	 * Documents the trap rather than hiding it: the prefix is added here, so a claim
	 * value that already carries it produces an authority that matches nothing. Worth
	 * checking the issuer's claim format when a role that should match does not.
	 */
	@Test
	@DisplayName("a ROLE_-prefixed claim value becomes ROLE_ROLE_ and matches nothing")
	void shouldDoublePrefixARoleThatAlreadyCarriesThePrefix() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", "roles");

		assertThat(authorities(converter, token("roles", List.of("ROLE_ADMIN")))).containsExactly("ROLE_ROLE_ADMIN");
	}

	@Test
	void shouldReturnNoAuthoritiesWhenTheClaimIsAbsent() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", "roles");

		assertThat(authorities(converter, token("sub", "ada"))).isEmpty();
	}

	@Test
	void shouldNotRepeatAnAuthorityPresentInBothClaims() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", "scope");

		assertThat(authorities(converter, token("scope", "shared"))).containsExactly("shared", "ROLE_shared");
	}

}
