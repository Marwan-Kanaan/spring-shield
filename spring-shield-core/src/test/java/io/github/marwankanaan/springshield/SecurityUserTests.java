package io.github.marwankanaan.springshield;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link SecurityUser}.
 *
 * @author mkanaan
 */
class SecurityUserTests {

	private static final SecurityRole ADMIN = SecurityRole.of("ADMIN");

	private static final SecurityPermission INVOICE_READ = SecurityPermission.of("invoice.read");

	@Test
	void shouldBuildAUserWithRolesAndPermissions() {
		SecurityUser user = SecurityUser.builder("ada").role(ADMIN).permission(INVOICE_READ).build();

		assertThat(user.username()).isEqualTo("ada");
		assertThat(user.roles()).containsExactly(ADMIN);
		assertThat(user.permissions()).containsExactly(INVOICE_READ);
	}

	@Test
	void shouldBuildAUserWithNoRolesOrPermissions() {
		SecurityUser user = SecurityUser.builder("ada").build();

		assertThat(user.roles()).isEmpty();
		assertThat(user.permissions()).isEmpty();
	}

	@Test
	@DisplayName("account status defaults to active, matching Spring Security's User builder")
	void shouldDefaultToAnActiveAccount() {
		SecurityUser user = SecurityUser.builder("ada").build();

		assertThat(user.enabled()).isTrue();
		assertThat(user.accountNonExpired()).isTrue();
		assertThat(user.accountNonLocked()).isTrue();
		assertThat(user.credentialsNonExpired()).isTrue();
	}

	@Test
	void shouldRecordEachAccountStatusFlagIndependently() {
		SecurityUser user = SecurityUser.builder("ada")
			.enabled(false)
			.accountNonExpired(false)
			.accountNonLocked(false)
			.credentialsNonExpired(false)
			.build();

		assertThat(user.enabled()).isFalse();
		assertThat(user.accountNonExpired()).isFalse();
		assertThat(user.accountNonLocked()).isFalse();
		assertThat(user.credentialsNonExpired()).isFalse();
	}

	@Test
	void shouldAddRolesAndPermissionsInBulkWithoutDiscardingEarlierOnes() {
		SecurityRole auditor = SecurityRole.of("AUDITOR");

		SecurityUser user = SecurityUser.builder("ada").role(ADMIN).roles(Set.of(auditor)).build();

		assertThat(user.roles()).containsExactlyInAnyOrder(ADMIN, auditor);
	}

	@Test
	void shouldIgnoreDuplicateRolesAndPermissions() {
		SecurityUser user = SecurityUser.builder("ada")
			.role(ADMIN)
			.role(SecurityRole.of("ADMIN"))
			.permission(INVOICE_READ)
			.permission(SecurityPermission.of("invoice.read"))
			.build();

		assertThat(user.roles()).hasSize(1);
		assertThat(user.permissions()).hasSize(1);
	}

	/**
	 * A user's authorities must not change after the security decision has been made. If
	 * the set were stored by reference, an application that reused and mutated its
	 * collection would retroactively alter the permissions of an already-built user.
	 */
	@Test
	void shouldNotBeAffectedByLaterChangesToTheCollectionItWasBuiltFrom() {
		Set<SecurityPermission> mutable = new HashSet<>();
		mutable.add(INVOICE_READ);

		SecurityUser user = SecurityUser.builder("ada").permissions(mutable).build();
		mutable.add(SecurityPermission.of("invoice.delete"));

		assertThat(user.permissions()).containsExactly(INVOICE_READ);
	}

	@Test
	void shouldNotBeAffectedByLaterChangesToTheBuilderThatCreatedIt() {
		SecurityUser.Builder builder = SecurityUser.builder("ada").role(ADMIN);
		SecurityUser user = builder.build();

		builder.role(SecurityRole.of("AUDITOR"));

		assertThat(user.roles()).containsExactly(ADMIN);
	}

	@Test
	void shouldExposeRolesAndPermissionsAsUnmodifiableSets() {
		SecurityUser user = SecurityUser.builder("ada").role(ADMIN).permission(INVOICE_READ).build();

		assertThatExceptionOfType(UnsupportedOperationException.class)
			.isThrownBy(() -> user.roles().add(SecurityRole.of("HACKER")));
		assertThatExceptionOfType(UnsupportedOperationException.class)
			.isThrownBy(() -> user.permissions().add(SecurityPermission.of("invoice.delete")));
	}

	@Test
	void shouldTrimTheUsername() {
		assertThat(SecurityUser.builder("  ada  ").build().username()).isEqualTo("ada");
	}

	@Test
	void shouldRejectNullUsername() {
		assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> SecurityUser.builder(null).build())
			.withMessageContaining("username");
	}

	@ParameterizedTest
	@ValueSource(strings = { "", "   ", "\t" })
	void shouldRejectBlankUsername(String username) {
		assertThatIllegalArgumentException().isThrownBy(() -> SecurityUser.builder(username).build())
			.withMessageContaining("username must not be blank");
	}

	@Test
	void shouldRejectNullRole() {
		assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> SecurityUser.builder("ada").role(null))
			.withMessageContaining("role must not be null");
	}

	@Test
	void shouldRejectNullPermission() {
		assertThatExceptionOfType(NullPointerException.class)
			.isThrownBy(() -> SecurityUser.builder("ada").permission(null))
			.withMessageContaining("permission must not be null");
	}

	/**
	 * A null inside an authority set would become a null authority, which tends to
	 * surface much later as a confusing failure inside an authorization check.
	 */
	@Test
	void shouldRejectANullElementInsideARoleSetPassedToTheConstructor() {
		Set<SecurityRole> withNull = new HashSet<>();
		withNull.add(ADMIN);
		withNull.add(null);

		assertThatExceptionOfType(NullPointerException.class)
			.isThrownBy(() -> new SecurityUser("ada", Optional.empty(), withNull, Set.of(), true, true, true, true));
	}

	@Test
	void shouldRejectNullRoleSet() {
		assertThatExceptionOfType(NullPointerException.class)
			.isThrownBy(() -> new SecurityUser("ada", Optional.empty(), null, Set.of(), true, true, true, true))
			.withMessageContaining("roles must not be null");
	}

	@Test
	void shouldRejectNullPermissionSet() {
		assertThatExceptionOfType(NullPointerException.class)
			.isThrownBy(() -> new SecurityUser("ada", Optional.empty(), Set.of(), null, true, true, true, true))
			.withMessageContaining("permissions must not be null");
	}

	@Test
	void shouldBeEqualWhenAllComponentsMatch() {
		SecurityUser first = SecurityUser.builder("ada").role(ADMIN).permission(INVOICE_READ).build();
		SecurityUser second = SecurityUser.builder("ada").role(ADMIN).permission(INVOICE_READ).build();

		assertThat(first).isEqualTo(second).hasSameHashCodeAs(second);
	}

	@Test
	void shouldNotBeEqualWhenAccountStatusDiffers() {
		SecurityUser active = SecurityUser.builder("ada").build();
		SecurityUser disabled = SecurityUser.builder("ada").enabled(false).build();

		assertThat(active).isNotEqualTo(disabled);
	}

}
