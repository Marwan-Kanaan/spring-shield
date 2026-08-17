package io.github.marwankanaan.springshield.autoconfigure;

import io.github.marwankanaan.springshield.RequiresPermission;
import io.github.marwankanaan.springshield.RequiresRole;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.stereotype.Service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNoException;

/**
 * End-to-end enforcement of {@link RequiresPermission} and {@link RequiresRole}.
 *
 * <p>
 * These invoke real Spring beans so the annotations are enforced through Spring
 * Security's method authorization. Asserting that the auto-configuration wired something
 * up would not show whether a caller lacking the permission is actually stopped.
 *
 * @author mkanaan
 */
@SpringBootTest(classes = { MethodSecurityIntegrationTests.TestApplication.class,
		MethodSecurityIntegrationTests.InvoiceService.class })
class MethodSecurityIntegrationTests {

	@Autowired
	private InvoiceService invoices;

	@Test
	@WithMockUser(authorities = "invoice.read")
	void shouldAllowACallerHoldingTheRequiredPermission() {
		assertThat(this.invoices.read()).isEqualTo("invoices");
	}

	/**
	 * The central negative case. Being authenticated is not enough.
	 */
	@Test
	@WithMockUser(authorities = "invoice.write")
	void shouldDenyACallerHoldingADifferentPermission() {
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.invoices.read());
	}

	@Test
	@WithMockUser
	void shouldDenyAnAuthenticatedCallerHoldingNoPermissions() {
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.invoices.read());
	}

	@Test
	@WithAnonymousUser
	void shouldDenyAnAnonymousCaller() {
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.invoices.read());
	}

	@Test
	void shouldDenyWhenThereIsNoAuthenticationAtAll() {
		assertThatExceptionOfType(AuthenticationCredentialsNotFoundException.class)
			.isThrownBy(() -> this.invoices.read());
	}

	/**
	 * Permissions are matched exactly. A near miss must not be treated as a match.
	 */
	@Test
	@WithMockUser(authorities = "invoice.readonly")
	void shouldNotTreatAPermissionWithAMatchingPrefixAsAMatch() {
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.invoices.read());
	}

	@Test
	@WithMockUser(authorities = "INVOICE.READ")
	@DisplayName("permission matching is case-sensitive")
	void shouldNotMatchAPermissionThatDiffersOnlyByCase() {
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.invoices.read());
	}

	@Test
	@WithMockUser(roles = "ADMIN")
	void shouldAllowACallerHoldingTheRequiredRole() {
		assertThatNoException().isThrownBy(() -> this.invoices.deleteAll());
	}

	@Test
	@WithMockUser(roles = "USER")
	void shouldDenyACallerHoldingADifferentRole() {
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.invoices.deleteAll());
	}

	/**
	 * A role is stored as an authority with a {@code ROLE_} prefix. Holding the bare
	 * authority {@code ADMIN} is therefore not the same as holding the role, and must not
	 * grant access.
	 */
	@Test
	@WithMockUser(authorities = "ADMIN")
	void shouldDenyACallerHoldingTheRoleNameAsAPlainAuthority() {
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> this.invoices.deleteAll());
	}

	@Test
	@WithMockUser(authorities = "invoice.read")
	void shouldNotGuardAnUnannotatedMethod() {
		assertThat(this.invoices.unguarded()).isEqualTo("open");
	}

	/**
	 * Application under test.
	 *
	 * @author mkanaan
	 */
	@SpringBootApplication
	static class TestApplication {

	}

	/**
	 * The service under test, carrying the annotations being enforced.
	 *
	 * @author mkanaan
	 */
	@Service
	static class InvoiceService {

		@RequiresPermission("invoice.read")
		String read() {
			return "invoices";
		}

		@RequiresRole("ADMIN")
		void deleteAll() {
		}

		String unguarded() {
			return "open";
		}

	}

}
