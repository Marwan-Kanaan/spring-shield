package io.github.marwankanaan.springshield.autoconfigure;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import io.github.marwankanaan.springshield.RequiresPermission;
import io.github.marwankanaan.springshield.RequiresRole;
import io.github.marwankanaan.springshield.SecurityPermission;
import io.github.marwankanaan.springshield.SecurityPermissionProvider;
import io.github.marwankanaan.springshield.SecurityRole;
import io.github.marwankanaan.springshield.SecurityUser;
import io.github.marwankanaan.springshield.SecurityUserProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;

/**
 * An application's own {@link SecurityUserProvider}, driving real authentication.
 *
 * <p>
 * Signs in over HTTP Basic against a provider backed by an in-memory user store, so the
 * whole path is exercised: the provider lookup, password verification against the encoded
 * hash, role expansion through {@link SecurityPermissionProvider}, and the annotations
 * authorizing against the resulting authorities.
 *
 * @author mkanaan
 */
@SpringBootTest(classes = { SecurityUserProviderIntegrationTests.TestApplication.class,
		SecurityUserProviderIntegrationTests.AccountController.class })
@AutoConfigureMockMvc
class SecurityUserProviderIntegrationTests {

	@Autowired
	private MockMvc mvc;

	@Test
	@DisplayName("a permission held directly by the user satisfies @RequiresPermission")
	void shouldAuthenticateAndAuthorizeAgainstADirectPermission() throws Exception {
		this.mvc.perform(get("/api/accounts").with(httpBasic("ada", "secret"))).andExpect(status().isOk());
	}

	/**
	 * The reason the permission provider exists: the user record carries only the role
	 * {@code ADMIN}, and the permission it grants is resolved separately.
	 */
	@Test
	@DisplayName("a permission granted by the user's role is expanded and authorizes")
	void shouldAuthorizeAgainstAPermissionExpandedFromARole() throws Exception {
		this.mvc.perform(get("/api/accounts/audit").with(httpBasic("ada", "secret"))).andExpect(status().isOk());
	}

	@Test
	void shouldAuthorizeAgainstARoleHeldByTheUser() throws Exception {
		this.mvc.perform(get("/api/accounts/admin").with(httpBasic("ada", "secret"))).andExpect(status().isOk());
	}

	@Test
	void shouldDenyAUserWhoseRoleGrantsNeitherThePermissionNorTheRole() throws Exception {
		this.mvc.perform(get("/api/accounts/admin").with(httpBasic("bob", "hunter2")))
			.andExpect(status().isForbidden())
			.andExpect(jsonPath("$.code").value("ACCESS_DENIED"));
	}

	@Test
	void shouldRejectAWrongPassword() throws Exception {
		this.mvc.perform(get("/api/accounts").with(httpBasic("ada", "wrong")))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
	}

	/**
	 * An unknown username must look exactly like a wrong password, or the difference lets
	 * an attacker discover which accounts exist.
	 */
	@Test
	@DisplayName("an unknown user is rejected the same way as a wrong password")
	void shouldRejectAnUnknownUsernameIndistinguishably() throws Exception {
		this.mvc.perform(get("/api/accounts").with(httpBasic("nobody", "secret")))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
	}

	@Test
	void shouldRejectADisabledAccount() throws Exception {
		this.mvc.perform(get("/api/accounts").with(httpBasic("dormant", "secret")))
			.andExpect(status().isUnauthorized());
	}

	/**
	 * An account that exists only for token access holds no password, so no password can
	 * sign it in. The empty stored hash can never match, which is why this fails closed
	 * rather than throwing.
	 */
	@Test
	@DisplayName("a user with no encoded password cannot be signed in with any password")
	void shouldRejectAnyPasswordForAnAccountWithNoPassword() throws Exception {
		this.mvc.perform(get("/api/accounts").with(httpBasic("tokenonly", ""))).andExpect(status().isUnauthorized());
		this.mvc.perform(get("/api/accounts").with(httpBasic("tokenonly", "anything")))
			.andExpect(status().isUnauthorized());
	}

	/**
	 * Application under test, publishing its own providers.
	 *
	 * @author mkanaan
	 */
	@SpringBootApplication
	static class TestApplication {

		private static final SecurityRole ADMIN = SecurityRole.of("ADMIN");

		private static final SecurityRole GUEST = SecurityRole.of("GUEST");

		/**
		 * A user store, standing in for a database.
		 * @param encoder the encoder SpringShield contributed, used to store hashes the
		 * way a real application would
		 * @return the provider
		 */
		@Bean
		SecurityUserProvider users(PasswordEncoder encoder) {
			Map<String, SecurityUser> store = Map.of("ada",
					SecurityUser.builder("ada")
						.encodedPassword(encoder.encode("secret"))
						.role(ADMIN)
						.permission(SecurityPermission.of("account.read"))
						.build(),
					"bob",
					SecurityUser.builder("bob")
						.encodedPassword(encoder.encode("hunter2"))
						.role(GUEST)
						.permission(SecurityPermission.of("account.read"))
						.build(),
					"dormant",
					SecurityUser.builder("dormant")
						.encodedPassword(encoder.encode("secret"))
						.enabled(false)
						.permission(SecurityPermission.of("account.read"))
						.build(),
					"tokenonly",
					SecurityUser.builder("tokenonly").permission(SecurityPermission.of("account.read")).build());
			return (username) -> Optional.ofNullable(store.get(username));
		}

		/**
		 * Role-to-permission mapping, standing in for a permissions table.
		 * @return the provider
		 */
		@Bean
		SecurityPermissionProvider permissions() {
			return (roles) -> roles.contains(ADMIN) ? Set.of(SecurityPermission.of("account.audit")) : Set.of();
		}

	}

	/**
	 * Endpoints guarded by a direct permission, an expanded permission, and a role.
	 *
	 * @author mkanaan
	 */
	@RestController
	static class AccountController {

		@GetMapping("/api/accounts")
		@RequiresPermission("account.read")
		String accounts() {
			return "accounts";
		}

		@GetMapping("/api/accounts/audit")
		@RequiresPermission("account.audit")
		String audit() {
			return "audit";
		}

		@GetMapping("/api/accounts/admin")
		@RequiresRole("ADMIN")
		String admin() {
			return "admin";
		}

	}

}
