package io.github.marwankanaan.springshield.autoconfigure;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

import io.github.marwankanaan.springshield.SecurityPermission;
import io.github.marwankanaan.springshield.SecurityPermissionProvider;
import io.github.marwankanaan.springshield.SecurityRole;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

/**
 * Turns the claims of a validated token into the authorities SpringShield authorizes
 * against.
 *
 * <p>
 * Three sources are combined, and each is mapped the way its half of the model expects:
 *
 * <pre>
 * permissions claim   invoice.read  -&gt;  authority  invoice.read
 * roles claim         ADMIN         -&gt;  authority  ROLE_ADMIN
 * roles expanded by SecurityPermissionProvider, added as permissions
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
 * <h2>Role expansion runs on every request</h2>
 *
 * <p>
 * Bearer token authentication is stateless: the token is converted afresh on each
 * request, so {@link SecurityPermissionProvider#findPermissions} is called on each
 * request too. That is unlike the username and password path, where it runs once at
 * sign-in.
 *
 * <p>
 * A provider that queries a database on every call therefore adds a query to every
 * authenticated request. Keep the implementation cheap, or cache inside it with an
 * invalidation strategy you have thought about. Leaving the roles claim unconfigured
 * skips expansion entirely, which is the right choice when the token already carries
 * permissions.
 *
 * <h2>Roles must be bare names</h2>
 *
 * <p>
 * A role claim value must be {@code ADMIN}, not {@code ROLE_ADMIN}. The prefix is added
 * here, so a value that already carries it becomes {@code ROLE_ROLE_ADMIN} and matches
 * nothing. That failure is silent, in the sense that the request is simply denied, so it
 * is worth checking the issuer's claim format when a role that should match does not.
 *
 * <p>
 * A claim value that cannot form a {@link SecurityRole} at all, because it is already
 * prefixed or contains a delimiter, still becomes an authority but is skipped when
 * expanding. There is nothing sensible to look it up as, and failing the whole request
 * over one unexpected claim value would take an application down for a change at its
 * identity provider.
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

	private final JwtGrantedAuthoritiesConverter permissionsConverter;

	private final JwtGrantedAuthoritiesConverter rolesConverter;

	private final JwtGrantedAuthoritiesConverter bareRolesConverter;

	private final SecurityPermissionProvider permissions;

	/**
	 * Creates the converter for the configured claim names.
	 * @param permissionsClaim claim holding permissions, never {@code null}
	 * @param rolesClaim claim holding roles, or {@code null} to read no roles
	 * @param permissions expands roles into the permissions they grant
	 */
	SpringShieldJwtAuthoritiesConverter(String permissionsClaim, String rolesClaim,
			SecurityPermissionProvider permissions) {
		this.permissions = permissions;
		this.permissionsConverter = claimConverter(permissionsClaim, "");
		this.rolesConverter = (rolesClaim != null) ? claimConverter(rolesClaim, "ROLE_") : null;
		// The same claim read a second time without a prefix, because expansion needs the
		// bare role names and the prefixed authorities cannot be turned back into them
		// reliably.
		this.bareRolesConverter = (rolesClaim != null) ? claimConverter(rolesClaim, "") : null;
	}

	private static JwtGrantedAuthoritiesConverter claimConverter(String claim, String prefix) {
		JwtGrantedAuthoritiesConverter converter = new JwtGrantedAuthoritiesConverter();
		converter.setAuthoritiesClaimName(claim);
		converter.setAuthorityPrefix(prefix);
		return converter;
	}

	/**
	 * Reads the configured claims and returns their combined authorities.
	 * @param jwt the validated token
	 * @return the authorities, never {@code null}, possibly empty
	 */
	@Override
	public Collection<GrantedAuthority> convert(Jwt jwt) {
		// A LinkedHashSet keeps the result stable and drops a duplicate that appears in
		// more
		// than one source, which would otherwise show up twice in the principal's
		// authorities.
		Set<GrantedAuthority> authorities = new LinkedHashSet<>(this.permissionsConverter.convert(jwt));
		if (this.rolesConverter == null) {
			return authorities;
		}
		authorities.addAll(this.rolesConverter.convert(jwt));
		Set<SecurityRole> roles = bareRoles(jwt);
		if (!roles.isEmpty()) {
			for (SecurityPermission granted : this.permissions.findPermissions(roles)) {
				authorities.add(new SimpleGrantedAuthority(granted.value()));
			}
		}
		return authorities;
	}

	/**
	 * Reads the roles claim as {@link SecurityRole} values, skipping anything that cannot
	 * be one.
	 * @param jwt the validated token
	 * @return the roles that can be expanded, never {@code null}
	 */
	private Set<SecurityRole> bareRoles(Jwt jwt) {
		Set<SecurityRole> roles = new LinkedHashSet<>();
		for (GrantedAuthority authority : this.bareRolesConverter.convert(jwt)) {
			try {
				roles.add(SecurityRole.of(authority.getAuthority()));
			}
			catch (IllegalArgumentException ex) {
				// Not a usable role name, so there is nothing to expand it as. It still
				// became a ROLE_ authority above; only the expansion is skipped.
			}
		}
		return roles;
	}

}
