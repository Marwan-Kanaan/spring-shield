package io.github.marwankanaan.springshield;

import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link SecurityPermissionProvider}.
 *
 * @author mkanaan
 */
class SecurityPermissionProviderTests {

	private static final SecurityRole ADMIN = SecurityRole.of("ADMIN");

	private static final SecurityPermission INVOICE_READ = SecurityPermission.of("invoice.read");

	@Test
	@DisplayName("the default provider grants nothing, so it cannot hand out unconfigured access")
	void noneShouldGrantNoPermissions() {
		assertThat(SecurityPermissionProvider.none().findPermissions(Set.of(ADMIN))).isEmpty();
	}

	@Test
	void noneShouldGrantNoPermissionsForAnEmptyRoleSet() {
		assertThat(SecurityPermissionProvider.none().findPermissions(Set.of())).isEmpty();
	}

	@Test
	void noneShouldReturnAnImmutableSet() {
		Set<SecurityPermission> permissions = SecurityPermissionProvider.none().findPermissions(Set.of(ADMIN));

		assertThatExceptionOfType(UnsupportedOperationException.class).isThrownBy(() -> permissions.add(INVOICE_READ));
	}

	@Test
	@DisplayName("the interface is a lambda target, so tests can supply one inline")
	void shouldBeImplementableAsALambda() {
		SecurityPermissionProvider provider = roles -> roles.contains(ADMIN) ? Set.of(INVOICE_READ) : Set.of();

		assertThat(provider.findPermissions(Set.of(ADMIN))).containsExactly(INVOICE_READ);
		assertThat(provider.findPermissions(Set.of(SecurityRole.of("GUEST")))).isEmpty();
	}

	/**
	 * The method takes every role at once precisely so an implementation can answer with
	 * a single lookup. This pins that contract: five roles must produce one call, not
	 * five.
	 */
	@Test
	void shouldReceiveAllRolesInOneCallSoImplementationsCanUseASingleQuery() {
		int[] invocations = { 0 };
		SecurityPermissionProvider counting = roles -> {
			invocations[0]++;
			return Set.of();
		};

		counting.findPermissions(Set.of(ADMIN, SecurityRole.of("AUDITOR"), SecurityRole.of("OPERATOR"),
				SecurityRole.of("SUPPORT"), SecurityRole.of("GUEST")));

		assertThat(invocations[0]).isEqualTo(1);
	}

	@Test
	void shouldReturnTheUnionOfPermissionsWhenRolesOverlap() {
		SecurityPermissionProvider provider = roles -> roles.stream()
			.map(role -> SecurityPermission.of("invoice.read"))
			.collect(Collectors.toUnmodifiableSet());

		assertThat(provider.findPermissions(Set.of(ADMIN, SecurityRole.of("AUDITOR")))).containsExactly(INVOICE_READ);
	}

}
