package io.github.marwankanaan.springshield;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link SecurityRole}.
 *
 * @author mkanaan
 */
class SecurityRoleTests {

	@Test
	void shouldExposeTheBareRoleName() {
		assertThat(SecurityRole.of("ADMIN").value()).isEqualTo("ADMIN");
	}

	@Test
	void shouldTrimSurroundingWhitespace() {
		assertThat(SecurityRole.of("  ADMIN  ").value()).isEqualTo("ADMIN");
	}

	@Test
	void shouldAddTheRolePrefixWhenConvertedToASpringSecurityAuthority() {
		assertThat(SecurityRole.of("ADMIN").asAuthority()).isEqualTo("ROLE_ADMIN");
	}

	/**
	 * Accepting a {@code ROLE_}-prefixed name would produce the authority
	 * {@code ROLE_ROLE_ADMIN}. Nothing would throw; every check for {@code ROLE_ADMIN}
	 * would simply stop matching and the user would silently lose access. Rejecting it
	 * converts a silent authorization bug into an immediate error.
	 */
	@Test
	void shouldRejectAnAlreadyPrefixedRoleToPreventDoublePrefixing() {
		assertThatIllegalArgumentException().isThrownBy(() -> SecurityRole.of("ROLE_ADMIN"))
			.withMessageContaining("must not start with 'ROLE_'")
			.withMessageContaining("use 'ADMIN' instead of 'ROLE_ADMIN'");
	}

	@Test
	void shouldRejectAPrefixedRoleEvenWithSurroundingWhitespace() {
		assertThatIllegalArgumentException().isThrownBy(() -> SecurityRole.of("  ROLE_USER  "));
	}

	@Test
	@DisplayName("the ROLE_ check is case-sensitive, so a lowercase role_admin is a legitimate name")
	void shouldAcceptALowercasePrefixLookalikeBecauseAuthoritiesAreCaseSensitive() {
		assertThat(SecurityRole.of("role_admin").asAuthority()).isEqualTo("ROLE_role_admin");
	}

	@Test
	void shouldRejectNullValue() {
		assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> SecurityRole.of(null))
			.withMessageContaining("role");
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "   ", "\t" })
	void shouldRejectBlankValue(String value) {
		assertThatIllegalArgumentException().isThrownBy(() -> SecurityRole.of(value))
			.withMessageContaining("must not be blank");
	}

	@ParameterizedTest
	@ValueSource(strings = { "SUPER ADMIN", "SUPER\tADMIN" })
	void shouldRejectInternalWhitespaceToPreventOneRoleSplittingIntoTwo(String value) {
		assertThatIllegalArgumentException().isThrownBy(() -> SecurityRole.of(value))
			.withMessageContaining("must not contain whitespace");
	}

	@ParameterizedTest
	@ValueSource(strings = { "ADMIN,USER", "ADMIN;USER" })
	void shouldRejectAuthorityDelimitersToPreventOneRoleSplittingIntoTwo(String value) {
		assertThatIllegalArgumentException().isThrownBy(() -> SecurityRole.of(value))
			.withMessageContaining("separates authorities");
	}

	@Test
	void shouldTreatDifferentCaseAsDifferentRoles() {
		assertThat(SecurityRole.of("ADMIN")).isNotEqualTo(SecurityRole.of("admin"));
	}

	@Test
	void shouldBeEqualWhenValuesMatchSoRolesWorkInSets() {
		assertThat(SecurityRole.of("ADMIN")).isEqualTo(SecurityRole.of("ADMIN"))
			.hasSameHashCodeAs(SecurityRole.of("ADMIN"));
	}

	@Test
	void shouldPrintTheBareNameSoLogsStayReadable() {
		assertThat(SecurityRole.of("ADMIN")).hasToString("ADMIN");
	}

}
