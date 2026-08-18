package io.github.marwankanaan.springshield.test;

import java.util.ArrayList;
import java.util.List;

import io.github.marwankanaan.springshield.SecurityPermission;
import io.github.marwankanaan.springshield.SecurityRole;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

/**
 * Builds the security context behind {@link WithSecurityUser}.
 *
 * <p>
 * This class is internal; Spring Security's test support instantiates it. Use the
 * annotation.
 *
 * <p>
 * The mapping is exactly what SpringShield applies in production: a permission becomes an
 * authority verbatim, a role gains the {@code ROLE_} prefix. Values are built through
 * {@code SecurityRole} and {@code SecurityPermission}, so a malformed one fails the test
 * with the same message a misconfigured application would get, at the point the mistake
 * was made rather than as an unexplained access denied later.
 *
 * @author mkanaan
 */
final class WithSecurityUserSecurityContextFactory implements WithSecurityContextFactory<WithSecurityUser> {

	/**
	 * Credentials are never populated. This helper establishes what a caller may do, not
	 * how they proved who they are, and putting a placeholder password in the context
	 * would invite tests to assert against something meaningless.
	 */
	private static final Object NO_CREDENTIALS = null;

	@Override
	public SecurityContext createSecurityContext(WithSecurityUser annotation) {
		List<GrantedAuthority> authorities = new ArrayList<>();
		for (String role : annotation.roles()) {
			authorities.add(new SimpleGrantedAuthority(SecurityRole.of(role).asAuthority()));
		}
		for (String permission : annotation.permissions()) {
			authorities.add(new SimpleGrantedAuthority(SecurityPermission.of(permission).value()));
		}
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(
				UsernamePasswordAuthenticationToken.authenticated(annotation.username(), NO_CREDENTIALS, authorities));
		return context;
	}

}
