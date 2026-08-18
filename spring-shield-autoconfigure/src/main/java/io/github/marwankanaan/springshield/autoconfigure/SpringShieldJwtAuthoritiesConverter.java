package io.github.marwankanaan.springshield.autoconfigure;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

/**
 * Turns the claims of a validated token into the authorities SpringShield authorizes
 * against.
 *
 * <p>
 * Two claims are read, and each is mapped the way its half of the model expects:
 *
 * <pre>
 * permissions claim   invoice.read  -&gt;  authority  invoice.read
 * roles claim         ADMIN         -&gt;  authority  ROLE_ADMIN
 * </pre>
 *
 * <p>
 * That is what makes {@code @RequiresPermission("invoice.read")} and
 * {@code @RequiresRole("ADMIN")} work against a bearer token: the permission is matched
 * exactly, and the role gets the {@code ROLE_} prefix Spring Security looks for.
 *
 * <p>
 * The claim reading itself is Spring Security's {@code JwtGrantedAuthoritiesConverter},
 * which already handles a claim being either a space-delimited string or a list.
 * SpringShield only decides which claims to read and which prefix each gets.
 *
 * <h2>Roles must be bare names</h2>
 *
 * <p>
 * A role claim value must be {@code ADMIN}, not {@code ROLE_ADMIN}. The prefix is added
 * here, so a value that already carries it becomes {@code ROLE_ROLE_ADMIN} and matches
 * nothing. That failure is silent, in the sense that the request is simply denied, so it
 * is worth checking the issuer's claim format when a role that should match does not.
 *
 * <h2>Only validated claims</h2>
 *
 * <p>
 * This runs after the decoder has verified the signature and the validators have checked
 * issuer, audience and expiry. A token that failed any of those never reaches this
 * converter, so no unverified claim can become an authority.
 *
 * <p>
 * This class is internal. An application wanting different mapping should declare its own
 * {@code JwtAuthenticationConverter}.
 *
 * @author mkanaan
 */
final class SpringShieldJwtAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

	private final JwtGrantedAuthoritiesConverter permissions;

	private final JwtGrantedAuthoritiesConverter roles;

	/**
	 * Creates the converter for the configured claim names.
	 * @param permissionsClaim claim holding permissions, never {@code null}
	 * @param rolesClaim claim holding roles, or {@code null} to read no roles
	 */
	SpringShieldJwtAuthoritiesConverter(String permissionsClaim, String rolesClaim) {
		this.permissions = new JwtGrantedAuthoritiesConverter();
		this.permissions.setAuthoritiesClaimName(permissionsClaim);
		// No prefix: a permission is used verbatim, so the value in the token is the
		// value
		// @RequiresPermission is written against.
		this.permissions.setAuthorityPrefix("");
		if (rolesClaim != null) {
			this.roles = new JwtGrantedAuthoritiesConverter();
			this.roles.setAuthoritiesClaimName(rolesClaim);
			this.roles.setAuthorityPrefix("ROLE_");
		}
		else {
			this.roles = null;
		}
	}

	/**
	 * Reads both claims and returns their combined authorities.
	 * @param jwt the validated token
	 * @return the authorities, never {@code null}, possibly empty
	 */
	@Override
	public Collection<GrantedAuthority> convert(Jwt jwt) {
		// A LinkedHashSet keeps the result stable and drops a duplicate that appears in
		// both
		// claims, which would otherwise show up twice in the principal's authorities.
		Set<GrantedAuthority> authorities = new LinkedHashSet<>(this.permissions.convert(jwt));
		if (this.roles != null) {
			authorities.addAll(this.roles.convert(jwt));
		}
		return authorities;
	}

}
