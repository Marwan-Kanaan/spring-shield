package io.github.marwankanaan.springshield;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Requires the caller to hold a role before the method runs.
 *
 * <pre>
 * &#64;RequiresRole("ADMIN")
 * public void deleteUser(String username) {
 *     ...
 * }
 * </pre>
 *
 * <p>
 * A caller without the role is rejected with an {@code AccessDeniedException}, which
 * normally becomes HTTP 403. The method body never runs.
 *
 * <h2>Prefer permissions where you can</h2>
 *
 * <p>
 * Role checks scattered through an application are hard to change: adding a new kind of
 * user means finding and editing every {@code @RequiresRole} that should now also apply.
 * A {@link RequiresPermission} check keeps working when the role model is reorganized,
 * because only the role-to-permission mapping changes. Reach for this annotation when a
 * role really is the thing being checked, such as guarding an administrative operation.
 *
 * <h2>This is Spring Security, not a second engine</h2>
 *
 * <p>
 * The annotation is meta-annotated with {@link PreAuthorize}, so
 * {@code @RequiresRole("ADMIN")} is exactly equivalent to
 * {@code @PreAuthorize("hasRole('ADMIN')")} and is enforced by Spring Security's own
 * method authorization.
 *
 * <h2>Use the bare role name</h2>
 *
 * <p>
 * Write {@code @RequiresRole("ADMIN")}, not {@code @RequiresRole("ROLE_ADMIN")}. Spring
 * Security stores a role as an authority with a {@code ROLE_} prefix and adds that prefix
 * when checking, so a prefixed value here would look for {@code ROLE_ROLE_ADMIN} and
 * never match. That failure is silent: the check simply denies. {@link SecurityRole}
 * rejects a prefixed value for the same reason.
 *
 * <p>
 * Matching is case-sensitive, and uppercase is the usual convention.
 *
 * <h2>Limitations worth knowing</h2>
 *
 * <p>
 * Enforcement uses Spring proxies, which has two consequences that surprise people:
 *
 * <ul>
 * <li><strong>Self-invocation is not checked.</strong> If a method inside the same class
 * calls an annotated method directly, the call does not pass through the proxy and no
 * authorization runs. Put the annotated method on a different bean, or call it through an
 * injected reference to itself.</li>
 * <li><strong>Only Spring-managed beans are covered.</strong> An object created with
 * {@code new} is not proxied, so the annotation on it does nothing.</li>
 * </ul>
 *
 * <p>
 * The value must be a compile-time constant. It is expanded into a Spring Security
 * expression, so never build it from user input.
 *
 * <p>
 * Method security must be active for this to be enforced. SpringShield enables it by
 * default; setting {@code springshield.authorization.enabled=false} turns it off, and
 * then this annotation has no effect at all.
 *
 * @author mkanaan
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
@PreAuthorize("hasRole('{value}')")
public @interface RequiresRole {

	/**
	 * The bare role name the caller must hold, for example {@code ADMIN}.
	 *
	 * <p>
	 * Must be a compile-time constant, and must not include the {@code ROLE_} prefix,
	 * which Spring Security adds when checking.
	 * @return the required role
	 */
	String value();

}
