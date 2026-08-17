package io.github.marwankanaan.springshield;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link SecurityPermission}.
 *
 * @author mkanaan
 */
class SecurityPermissionTests {

	@Test
	void shouldExposeTheValueItWasCreatedWith() {
		assertThat(SecurityPermission.of("invoice.read").value()).isEqualTo("invoice.read");
	}

	@Test
	void shouldTrimSurroundingWhitespaceBecauseItIsAlwaysATypo() {
		assertThat(SecurityPermission.of("  invoice.read  ").value()).isEqualTo("invoice.read");
	}

	@Test
	void shouldAcceptASingleWordPermissionBecauseTheDottedConventionIsNotMandatory() {
		assertThat(SecurityPermission.of("audit").value()).isEqualTo("audit");
	}

	@Test
	void shouldRejectNullValue() {
		assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> SecurityPermission.of(null))
			.withMessageContaining("permission");
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "   ", "\t", "\n" })
	void shouldRejectBlankValue(String value) {
		assertThatIllegalArgumentException().isThrownBy(() -> SecurityPermission.of(value))
			.withMessageContaining("must not be blank");
	}

	/**
	 * Whitespace is rejected because authority values are serialized into space-delimited
	 * formats such as an OAuth2 scope claim. Allowing a space would let one permission
	 * split into two, granting access that was never configured.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "invoice read", "invoice\tread", "invoice\nread" })
	void shouldRejectInternalWhitespaceToPreventOnePermissionSplittingIntoTwo(String value) {
		assertThatIllegalArgumentException().isThrownBy(() -> SecurityPermission.of(value))
			.withMessageContaining("must not contain whitespace");
	}

	/**
	 * Commas and semicolons separate authorities in several common formats, including
	 * Spring Security's own comma-separated authority parsing.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "invoice.read,invoice.write", "invoice.read;admin", "a,b" })
	void shouldRejectAuthorityDelimitersToPreventOnePermissionSplittingIntoTwo(String value) {
		assertThatIllegalArgumentException().isThrownBy(() -> SecurityPermission.of(value))
			.withMessageContaining("separates authorities");
	}

	@Test
	@DisplayName("comparison is case-sensitive, so USER.READ does not equal user.read")
	void shouldTreatDifferentCaseAsDifferentPermissions() {
		assertThat(SecurityPermission.of("user.read")).isNotEqualTo(SecurityPermission.of("USER.READ"));
	}

	@Test
	void shouldBeEqualWhenValuesMatchSoPermissionsWorkInSets() {
		assertThat(SecurityPermission.of("user.read")).isEqualTo(SecurityPermission.of("user.read"))
			.hasSameHashCodeAs(SecurityPermission.of("user.read"));
	}

	@Test
	void shouldPrintTheBareValueSoLogsStayReadable() {
		assertThat(SecurityPermission.of("invoice.read")).hasToString("invoice.read");
	}

}
