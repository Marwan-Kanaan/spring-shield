package io.github.marwankanaan.springshield.test;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.security.test.context.support.WithSecurityContext;

/**
 * Runs a test as a caller holding the given roles and permissions.
 *
 * <pre>
 * &#64;Test
 * &#64;WithSecurityUser(permissions = "invoice.read")
 * void shouldReturnInvoices() {
 *     assertThat(this.invoices.findAll()).isNotEmpty();
 * }
 *
 * &#64;Test
 * &#64;WithSecurityUser(roles = "ADMIN")
 * void shouldAllowAnAdministratorToDelete() {
 *     this.invoices.deleteAll();
 * }
 * </pre>
 *
 * <p>
 * Spring Security's {@code @WithMockUser} can do the same thing, but only if you already
 * know how SpringShield maps its model onto authorities: permissions verbatim, roles with
 * a {@code ROLE_} prefix. Getting that wrong produces a test that fails for a reason
 * unrelated to the code under test. This annotation applies the mapping for you, so a
 * test says what it means.
 *
 * <h2>Requires a Spring test context</h2>
 *
 * <p>
 * Like {@code @WithMockUser}, this is applied by a Spring test execution listener, so the
 * test has to run with the Spring test context: {@code @SpringBootTest}, a slice such as
 * {@code @WebMvcTest}, or {@code @ExtendWith(SpringExtension.class)}. On a plain JUnit
 * test the annotation is ignored silently and the security context stays empty, which
 * surfaces as a null authentication rather than a helpful error.
 *
 * <h2>Values are validated</h2>
 *
 * <p>
 * Roles and permissions go through {@code SecurityRole} and {@code SecurityPermission},
 * so the same rules apply as in production code. Writing {@code roles = "ROLE_ADMIN"}
 * fails the test immediately with an explanation, rather than silently producing
 * {@code ROLE_ROLE_ADMIN} and an access denied you then have to diagnose.
 *
 * <h2>What this does not do</h2>
 *
 * <p>
 * It populates the security context and nothing else. It does not disable a check, skip
 * the filter chain, or grant an authority the application would not have granted. A test
 * using it exercises the same authorization code a real request does, which is the point:
 * a helper that bypassed security would prove nothing about it.
 *
 * <p>
 * It also does not authenticate. There is no password and no token here, so this tests
 * what a caller may do once authenticated, not whether they can authenticate. Cover the
 * sign-in path with a real request.
 *
 * @author mkanaan
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@WithSecurityContext(factory = WithSecurityUserSecurityContextFactory.class)
public @interface WithSecurityUser {

	/**
	 * The username the test runs as.
	 * @return the username, defaulting to {@code user}
	 */
	String username() default "user";

	/**
	 * Roles the caller holds, as bare names such as {@code ADMIN}.
	 *
	 * <p>
	 * Do not include the {@code ROLE_} prefix; it is added when mapping to an authority,
	 * and a value that already carries it is rejected.
	 * @return the roles, empty by default
	 */
	String[] roles() default {};

	/**
	 * Permissions the caller holds, such as {@code invoice.read}.
	 *
	 * <p>
	 * Each becomes an authority verbatim, so the value here is the value
	 * {@code @RequiresPermission} is written against.
	 * @return the permissions, empty by default
	 */
	String[] permissions() default {};

}
