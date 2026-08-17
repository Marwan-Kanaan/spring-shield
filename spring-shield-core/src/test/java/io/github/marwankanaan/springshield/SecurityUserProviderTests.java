package io.github.marwankanaan.springshield;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link SecurityUserProvider}.
 *
 * @author mkanaan
 */
class SecurityUserProviderTests {

	private static final SecurityUser ADA = SecurityUser.builder("ada").role(SecurityRole.of("ADMIN")).build();

	private final SecurityUserProvider provider = username -> Optional.ofNullable(Map.of("ada", ADA).get(username));

	@Test
	void shouldReturnTheUserWhenOneMatches() {
		assertThat(this.provider.findByUsername("ada")).contains(ADA);
	}

	/**
	 * A missing user is an ordinary lookup outcome, not an error. Returning empty rather
	 * than throwing lets SpringShield report the same failure it reports for a wrong
	 * password, which is what stops an attacker distinguishing the two.
	 */
	@Test
	void shouldReturnEmptyRatherThanThrowWhenNoUserMatches() {
		assertThat(this.provider.findByUsername("nobody")).isEmpty();
	}

	@Test
	@DisplayName("lookup is case-sensitive unless an implementation chooses otherwise")
	void shouldNotMatchADifferentlyCasedUsernameByDefault() {
		assertThat(this.provider.findByUsername("ADA")).isEmpty();
	}

	@Test
	@DisplayName("the interface is a lambda target, so tests can supply one inline")
	void shouldBeImplementableAsALambda() {
		SecurityUserProvider always = username -> Optional.of(SecurityUser.builder(username).build());

		assertThat(always.findByUsername("anyone")).map(SecurityUser::username).contains("anyone");
	}

	@Test
	void shouldReturnAUserCarryingTheRolesTheImplementationPopulated() {
		assertThat(this.provider.findByUsername("ada")).get()
			.extracting(SecurityUser::roles)
			.isEqualTo(Set.of(SecurityRole.of("ADMIN")));
	}

}
