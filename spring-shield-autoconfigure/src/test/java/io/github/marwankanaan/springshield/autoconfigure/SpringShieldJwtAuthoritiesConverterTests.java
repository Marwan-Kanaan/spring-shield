package io.github.marwankanaan.springshield.autoconfigure;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import io.github.marwankanaan.springshield.SecurityPermission;
import io.github.marwankanaan.springshield.SecurityPermissionProvider;
import io.github.marwankanaan.springshield.SecurityRole;

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
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", null,
				SecurityPermissionProvider.none());

		assertThat(authorities(converter, token("scope", "invoice.read"))).containsExactly("invoice.read");
	}

	@Test
	@DisplayName("the standard scope claim may be a space-delimited string")
	void shouldSplitASpaceDelimitedScopeClaim() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", null,
				SecurityPermissionProvider.none());

		assertThat(authorities(converter, token("scope", "invoice.read invoice.export")))
			.containsExactlyInAnyOrder("invoice.read", "invoice.export");
	}

	@Test
	void shouldReadAPermissionsClaimGivenAsAList() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("permissions", null,
				SecurityPermissionProvider.none());

		assertThat(authorities(converter, token("permissions", List.of("invoice.read", "invoice.export"))))
			.containsExactlyInAnyOrder("invoice.read", "invoice.export");
	}

	@Test
	@DisplayName("a role gains the ROLE_ prefix Spring Security expects")
	void shouldMapRolesWithTheRolePrefix() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", "roles",
				SecurityPermissionProvider.none());

		assertThat(authorities(converter, token("roles", List.of("ADMIN")))).containsExactly("ROLE_ADMIN");
	}

	@Test
	void shouldCombinePermissionsAndRolesFromSeparateClaims() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", "roles",
				SecurityPermissionProvider.none());
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
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", null,
				SecurityPermissionProvider.none());
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
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", "roles",
				SecurityPermissionProvider.none());

		assertThat(authorities(converter, token("roles", List.of("ROLE_ADMIN")))).containsExactly("ROLE_ROLE_ADMIN");
	}

	@Test
	void shouldReturnNoAuthoritiesWhenTheClaimIsAbsent() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", "roles",
				SecurityPermissionProvider.none());

		assertThat(authorities(converter, token("sub", "ada"))).isEmpty();
	}

	@Test
	void shouldNotRepeatAnAuthorityPresentInBothClaims() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", "scope",
				SecurityPermissionProvider.none());

		assertThat(authorities(converter, token("scope", "shared"))).containsExactly("shared", "ROLE_shared");
	}

	/**
	 * The reason SecurityPermissionProvider exists on the token path: the token carries
	 * only a role, and the permission it grants is resolved separately.
	 */
	@Test
	@DisplayName("a role from the token is expanded into the permissions it grants")
	void shouldExpandRolesIntoPermissions() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", "roles",
				(roles) -> roles.contains(SecurityRole.of("ADMIN")) ? Set.of(SecurityPermission.of("invoice.approve"))
						: Set.of());

		assertThat(authorities(converter, token("roles", List.of("ADMIN")))).containsExactlyInAnyOrder("ROLE_ADMIN",
				"invoice.approve");
	}

	@Test
	void shouldNotExpandWhenNoRolesClaimIsConfigured() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", null,
				(roles) -> Set.of(SecurityPermission.of("should.not.appear")));

		assertThat(authorities(converter, token("scope", "invoice.read"))).containsExactly("invoice.read");
	}

	/**
	 * Expansion is skipped for a value that cannot be a role name at all. It still
	 * becomes an authority, so nothing is lost, but failing the whole request over one
	 * unexpected claim value would take an application down for a change at its identity
	 * provider.
	 */
	@Test
	@DisplayName("an unusable role value is still an authority, just not expanded")
	void shouldSkipExpansionForAValueThatCannotBeARoleName() {
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", "roles",
				(roles) -> Set.of(SecurityPermission.of("expanded")));

		assertThat(authorities(converter, token("roles", List.of("ROLE_ADMIN")))).containsExactly("ROLE_ROLE_ADMIN");
	}

	@Test
	void shouldNotCallTheProviderWhenTheTokenCarriesNoRoles() {
		int[] calls = { 0 };
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", "roles",
				(roles) -> {
					calls[0]++;
					return Set.of();
				});

		authorities(converter, token("scope", "invoice.read"));

		assertThat(calls[0]).isZero();
	}

	/**
	 * All roles reach the provider in one call, so a token with several roles still costs
	 * a single lookup on a path that runs at every request.
	 */
	@Test
	void shouldPassEveryRoleToTheProviderInOneCall() {
		int[] calls = { 0 };
		SpringShieldJwtAuthoritiesConverter converter = new SpringShieldJwtAuthoritiesConverter("scope", "roles",
				(roles) -> {
					calls[0]++;
					assertThat(roles).hasSize(3);
					return Set.of();
				});

		authorities(converter, token("roles", List.of("ADMIN", "AUDITOR", "OPERATOR")));

		assertThat(calls[0]).isEqualTo(1);
	}

}
