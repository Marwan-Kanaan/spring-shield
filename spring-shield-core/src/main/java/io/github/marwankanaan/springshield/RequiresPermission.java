package io.github.marwankanaan.springshield;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.security.access.prepost.PreAuthorize;

/**
 * Requires the caller to hold a permission before the method runs.
 *
 * <pre>
 * &#64;RequiresPermission("invoice.read")
 * public List&lt;Invoice&gt; findInvoices() {
 *     ...
 * }
 * </pre>
 *
 * <p>
 * A caller without the permission is rejected with an {@code AccessDeniedException},
 * which normally becomes HTTP 403. The method body never runs.
 *
 * <h2>This is Spring Security, not a second engine</h2>
 *
 * <p>
 * The annotation is meta-annotated with {@link PreAuthorize}, so it is a genuine Spring
 * Security annotation. Writing {@code @RequiresPermission("invoice.read")} is exactly
 * equivalent to writing {@code @PreAuthorize("hasAuthority('invoice.read')")}, and it is
 * enforced by the same method authorization Spring Security uses for its own annotations.
 * SpringShield contributes no authorization logic of its own here.
 *
 * <p>
 * The practical consequence is that it composes: you can mix it freely with
 * {@code @PreAuthorize}, {@code @PostAuthorize} and a custom
 * {@code AuthorizationManager}, and it participates in Spring Security's authorization
 * events.
 *
 * <h2>Permissions are authorities</h2>
 *
 * <p>
 * The value is matched against the caller's granted authorities exactly, and matching is
 * case-sensitive. A caller authorized for {@code invoice.read} must hold an authority
 * whose name is precisely {@code invoice.read}. See {@link SecurityPermission} for the
 * naming rules.
 *
 * <p>
 * Note that roles are stored as authorities with a {@code ROLE_} prefix, so this
 * annotation is not the way to check a role. Use {@link RequiresRole} for that.
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
@PreAuthorize("hasAuthority('{value}')")
public @interface RequiresPermission {

	/**
	 * The permission the caller must hold, for example {@code invoice.read}.
	 *
	 * <p>
	 * Must be a compile-time constant, and is matched against the caller's authorities
	 * exactly, including case.
	 * @return the required permission
	 */
	String value();

}
