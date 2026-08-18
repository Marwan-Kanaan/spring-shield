package io.github.marwankanaan.springshield.test;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Behaviour of {@link WithSecurityUser}.
 *
 * <p>
 * These check the exact authority strings placed in the context, because that is the
 * whole value of the annotation: an authority mapped the wrong way produces a test that
 * fails for a reason unrelated to the code under test.
 *
 * @author mkanaan
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(classes = WithSecurityUserTests.EmptyConfiguration.class)
class WithSecurityUserTests {

	/**
	 * The annotation is processed by a Spring test execution listener, so a context has
	 * to exist. It needs nothing in it.
	 *
	 * @author mkanaan
	 */
	@Configuration
	static class EmptyConfiguration {

	}

	private static List<String> currentAuthorities() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		return authentication.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();
	}

	@Test
	@WithSecurityUser(permissions = "invoice.read")
	@DisplayName("a permission becomes an authority verbatim")
	void shouldMapAPermissionWithoutAPrefix() {
		assertThat(currentAuthorities()).containsExactly("invoice.read");
	}

	@Test
	@WithSecurityUser(roles = "ADMIN")
	@DisplayName("a role gains the ROLE_ prefix Spring Security expects")
	void shouldMapARoleWithTheRolePrefix() {
		assertThat(currentAuthorities()).containsExactly("ROLE_ADMIN");
	}

	@Test
	@WithSecurityUser(roles = { "ADMIN", "AUDITOR" }, permissions = { "invoice.read", "invoice.export" })
	void shouldMapRolesAndPermissionsTogether() {
		assertThat(currentAuthorities()).containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_AUDITOR", "invoice.read",
				"invoice.export");
	}

	@Test
	@WithSecurityUser(username = "ada", permissions = "invoice.read")
	void shouldUseTheGivenUsername() {
		assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo("ada");
	}

	@Test
	@WithSecurityUser
	void shouldDefaultToAnAuthenticatedCallerWithNoAuthorities() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		assertThat(authentication.isAuthenticated()).isTrue();
		assertThat(authentication.getName()).isEqualTo("user");
		assertThat(currentAuthorities()).isEmpty();
	}

	/**
	 * Credentials are deliberately absent. The annotation establishes what a caller may
	 * do, not how they proved who they are.
	 */
	@Test
	@WithSecurityUser(permissions = "invoice.read")
	void shouldNotPopulateCredentials() {
		assertThat(SecurityContextHolder.getContext().getAuthentication().getCredentials()).isNull();
	}

	/**
	 * The trap this annotation exists to prevent. Left to {@code @WithMockUser}, a
	 * {@code ROLE_}-prefixed value would silently become {@code ROLE_ROLE_ADMIN} and deny
	 * access for a reason the test author would have to work out.
	 */
	@Test
	@DisplayName("a ROLE_-prefixed role is rejected rather than silently double-prefixed")
	void shouldRejectARolePrefixedValue() {
		WithSecurityUser annotation = annotationWith(new String[] { "ROLE_ADMIN" }, new String[0]);

		assertThatIllegalArgumentException()
			.isThrownBy(() -> new WithSecurityUserSecurityContextFactory().createSecurityContext(annotation))
			.withMessageContaining("must not start with 'ROLE_'");
	}

	@Test
	void shouldRejectAPermissionContainingADelimiter() {
		WithSecurityUser annotation = annotationWith(new String[0], new String[] { "invoice.read,invoice.export" });

		assertThatIllegalArgumentException()
			.isThrownBy(() -> new WithSecurityUserSecurityContextFactory().createSecurityContext(annotation))
			.withMessageContaining("separates authorities");
	}

	/**
	 * Builds an annotation instance directly, so the rejection cases can be asserted.
	 * Applying them to a test method would fail the whole test rather than let the
	 * failure be checked.
	 * @param roles the roles to declare
	 * @param permissions the permissions to declare
	 * @return an annotation carrying those values
	 */
	private static WithSecurityUser annotationWith(String[] roles, String[] permissions) {
		return new WithSecurityUser() {

			@Override
			public Class<? extends java.lang.annotation.Annotation> annotationType() {
				return WithSecurityUser.class;
			}

			@Override
			public String username() {
				return "user";
			}

			@Override
			public String[] roles() {
				return roles;
			}

			@Override
			public String[] permissions() {
				return permissions;
			}

		};
	}

}
