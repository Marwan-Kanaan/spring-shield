package io.github.marwankanaan.springshield.autoconfigure;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import io.github.marwankanaan.springshield.SecurityPermission;
import io.github.marwankanaan.springshield.SecurityPermissionProvider;
import io.github.marwankanaan.springshield.SecurityRole;
import io.github.marwankanaan.springshield.SecurityUser;
import io.github.marwankanaan.springshield.SecurityUserProvider;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Makes an application's {@link SecurityUserProvider} usable by Spring Security.
 *
 * <p>
 * Spring Security authenticates through {@link UserDetailsService}. This adapts the
 * SpringShield provider to it, so an application implements one small interface returning
 * its own domain types and gets username and password authentication without touching
 * Spring Security's own types.
 *
 * <p>
 * This class is internal.
 *
 * <h2>How authorities are assembled</h2>
 *
 * <pre>
 * roles          ADMIN         -&gt;  ROLE_ADMIN
 * permissions    invoice.read  -&gt;  invoice.read
 * roles expanded by SecurityPermissionProvider, added as permissions
 * </pre>
 *
 * <p>
 * The expansion is what lets an application store only coarse roles against a user and
 * define separately what each role allows. It happens in one call for all roles, so a
 * user with several roles still costs a single lookup.
 *
 * <h2>Failure behaviour</h2>
 *
 * <p>
 * A missing user becomes {@link UsernameNotFoundException}, which is Spring Security's
 * contract here. That is not a leak: {@code DaoAuthenticationProvider} hides it behind a
 * generic bad-credentials failure by default and performs a dummy password check anyway,
 * so an unknown username takes about as long to reject as a known one and looks the same
 * to the caller.
 *
 * <p>
 * If the permission provider throws, the exception propagates and the sign-in fails. That
 * is deliberate: treating a lookup failure as "no extra permissions" would silently sign
 * a user in with fewer rights than they hold, which is confusing at best and, for an
 * account whose access depends entirely on role expansion, a lockout that looks like a
 * permissions bug.
 *
 * @author mkanaan
 */
class SecurityUserDetailsService implements UserDetailsService {

	/**
	 * Stands in for the password of an account that has none.
	 *
	 * <p>
	 * Spring Security's {@code User} rejects a null password, and an empty one can never
	 * match: {@code PasswordEncoder.matches} returns false whenever either side is empty.
	 * So a token-only account is representable and simply cannot be signed into with a
	 * password.
	 */
	private static final String NO_PASSWORD = "";

	private final SecurityUserProvider users;

	private final SecurityPermissionProvider permissions;

	SecurityUserDetailsService(SecurityUserProvider users, SecurityPermissionProvider permissions) {
		this.users = users;
		this.permissions = permissions;
	}

	@Override
	public UserDetails loadUserByUsername(String username) {
		SecurityUser user = this.users.findByUsername(username)
			.orElseThrow(() -> new UsernameNotFoundException("No user found"));
		return User.withUsername(user.username())
			.password(user.encodedPassword().orElse(NO_PASSWORD))
			.authorities(authorities(user))
			.disabled(!user.enabled())
			.accountExpired(!user.accountNonExpired())
			.accountLocked(!user.accountNonLocked())
			.credentialsExpired(!user.credentialsNonExpired())
			.build();
	}

	/**
	 * Combines the user's roles, their own permissions, and the permissions their roles
	 * grant.
	 * @param user the user just looked up
	 * @return the authorities Spring Security will authorize against
	 */
	private List<GrantedAuthority> authorities(SecurityUser user) {
		// A set so a permission held directly and also granted by a role appears once.
		Set<GrantedAuthority> authorities = new LinkedHashSet<>();
		for (SecurityRole role : user.roles()) {
			authorities.add(new SimpleGrantedAuthority(role.asAuthority()));
		}
		for (SecurityPermission permission : user.permissions()) {
			authorities.add(new SimpleGrantedAuthority(permission.value()));
		}
		for (SecurityPermission granted : this.permissions.findPermissions(user.roles())) {
			authorities.add(new SimpleGrantedAuthority(granted.value()));
		}
		return new ArrayList<>(authorities);
	}

}
