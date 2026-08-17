package io.github.marwankanaan.springshield;

import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

/**
 * An authenticated identity together with what it is allowed to do.
 *
 * <p>
 * This is the type an application hands back to SpringShield when it looks a user up. It
 * is a plain immutable value object: build one from your own user store, do not implement
 * it on a persistence entity.
 *
 * <pre>
 * SecurityUser user = SecurityUser.builder("ada")
 *     .role(SecurityRole.of("ADMIN"))
 *     .permission(SecurityPermission.of("invoice.read"))
 *     .build();
 * </pre>
 *
 * <h2>Why this is a value object and not an interface</h2>
 *
 * <p>
 * It would be convenient to let a JPA entity implement a {@code SecurityUser} interface,
 * but that turns out badly. A security decision would then read from a live entity whose
 * collections may be lazily loaded, so an authorization check running outside a
 * transaction can throw, and a detached entity can change underneath a cached decision.
 * Requiring an explicit copy keeps persistence concerns out of the authorization path and
 * makes the object safe to share between threads.
 *
 * <h2>No password</h2>
 *
 * <p>
 * There is deliberately no password here. Most SpringShield deployments authenticate with
 * JWT or OIDC, where no password exists at all, and a field that is meaningless in the
 * common case invites unsafe handling. Password verification stays inside Spring
 * Security's own components, which are built for it.
 *
 * <h2>Authorization</h2>
 *
 * <p>
 * There is no {@code hasPermission} method, again deliberately. Authorization is a policy
 * decision that belongs in Spring Security's authorization infrastructure, where it is
 * applied consistently and can be tested. A convenience check here would encourage ad-hoc
 * {@code if} statements scattered through controllers, which is exactly how authorization
 * gaps appear.
 *
 * <h2>Thread safety</h2>
 *
 * <p>
 * Instances are immutable and safe to share between threads. The role and permission sets
 * are defensively copied, so later changes to the collection you passed in do not affect
 * an existing user.
 *
 * @param username identifies the user, never blank
 * @param roles the roles held, never {@code null}, possibly empty, immutable
 * @param permissions the permissions held, never {@code null}, possibly empty, immutable
 * @param enabled whether the account is active; a disabled account must not authenticate
 * @param accountNonExpired whether the account has not expired
 * @param accountNonLocked whether the account is not locked, for example after repeated
 * failed sign-ins
 * @param credentialsNonExpired whether the credentials have not expired, for example a
 * password past its maximum age
 * @author mkanaan
 */
public record SecurityUser(String username, Set<SecurityRole> roles, Set<SecurityPermission> permissions,
		boolean enabled, boolean accountNonExpired, boolean accountNonLocked, boolean credentialsNonExpired) {

	/**
	 * Canonical constructor, which validates the username and defensively copies the role
	 * and permission sets.
	 *
	 * <p>
	 * Prefer {@link #builder(String)}. Four consecutive booleans are easy to transpose at
	 * a call site, and a transposed flag here is a security bug: swapping {@code enabled}
	 * and {@code accountNonLocked} would let a locked account through.
	 * @throws NullPointerException if any reference argument, or any element of
	 * {@code roles} or {@code permissions}, is {@code null}
	 * @throws IllegalArgumentException if {@code username} is blank
	 */
	public SecurityUser {
		Objects.requireNonNull(username, "username must not be null");
		username = username.trim();
		if (username.isEmpty()) {
			throw new IllegalArgumentException("username must not be blank");
		}
		Objects.requireNonNull(roles, "roles must not be null");
		Objects.requireNonNull(permissions, "permissions must not be null");
		// Set.copyOf both copies and rejects null elements, so a caller cannot leave a
		// null role in an authority set.
		roles = Set.copyOf(roles);
		permissions = Set.copyOf(permissions);
	}

	/**
	 * Starts building a user.
	 *
	 * <p>
	 * The account status flags default to an active account, matching the defaults of
	 * Spring Security's own {@code User} builder. If your user store has an "active" or
	 * "locked" column, map it explicitly with {@link Builder#enabled(boolean)} or
	 * {@link Builder#accountNonLocked(boolean)}. Forgetting to map it means a disabled
	 * account is treated as active.
	 * @param username identifies the user, must not be blank
	 * @return a new builder
	 */
	public static Builder builder(String username) {
		return new Builder(username);
	}

	/**
	 * Builds a {@link SecurityUser}.
	 *
	 * <p>
	 * Obtain one from {@link SecurityUser#builder(String)}. A builder is single use and
	 * is not thread-safe; the {@link SecurityUser} it produces is both immutable and
	 * thread-safe.
	 *
	 * <pre>
	 * SecurityUser user = SecurityUser.builder("ada")
	 *     .role(SecurityRole.of("ADMIN"))
	 *     .permissions(readPermissions)
	 *     .accountNonLocked(!account.isLocked())
	 *     .build();
	 * </pre>
	 *
	 * @author mkanaan
	 */
	public static final class Builder {

		private final String username;

		private final Set<SecurityRole> roles = new LinkedHashSet<>();

		private final Set<SecurityPermission> permissions = new LinkedHashSet<>();

		private boolean enabled = true;

		private boolean accountNonExpired = true;

		private boolean accountNonLocked = true;

		private boolean credentialsNonExpired = true;

		private Builder(String username) {
			this.username = username;
		}

		/**
		 * Adds one role.
		 * @param role the role to add, must not be {@code null}
		 * @return this builder
		 */
		public Builder role(SecurityRole role) {
			this.roles.add(Objects.requireNonNull(role, "role must not be null"));
			return this;
		}

		/**
		 * Adds several roles, keeping any already added.
		 * @param roles the roles to add, must not be {@code null}
		 * @return this builder
		 */
		public Builder roles(Iterable<SecurityRole> roles) {
			Objects.requireNonNull(roles, "roles must not be null");
			roles.forEach(this::role);
			return this;
		}

		/**
		 * Adds one permission.
		 * @param permission the permission to add, must not be {@code null}
		 * @return this builder
		 */
		public Builder permission(SecurityPermission permission) {
			this.permissions.add(Objects.requireNonNull(permission, "permission must not be null"));
			return this;
		}

		/**
		 * Adds several permissions, keeping any already added.
		 * @param permissions the permissions to add, must not be {@code null}
		 * @return this builder
		 */
		public Builder permissions(Iterable<SecurityPermission> permissions) {
			Objects.requireNonNull(permissions, "permissions must not be null");
			permissions.forEach(this::permission);
			return this;
		}

		/**
		 * Sets whether the account is active. Defaults to {@code true}.
		 * @param enabled {@code false} to prevent the account from authenticating
		 * @return this builder
		 */
		public Builder enabled(boolean enabled) {
			this.enabled = enabled;
			return this;
		}

		/**
		 * Sets whether the account has not expired. Defaults to {@code true}.
		 * @param accountNonExpired {@code false} if the account has expired
		 * @return this builder
		 */
		public Builder accountNonExpired(boolean accountNonExpired) {
			this.accountNonExpired = accountNonExpired;
			return this;
		}

		/**
		 * Sets whether the account is not locked. Defaults to {@code true}.
		 * @param accountNonLocked {@code false} if the account is locked
		 * @return this builder
		 */
		public Builder accountNonLocked(boolean accountNonLocked) {
			this.accountNonLocked = accountNonLocked;
			return this;
		}

		/**
		 * Sets whether the credentials have not expired. Defaults to {@code true}.
		 * @param credentialsNonExpired {@code false} if the credentials have expired
		 * @return this builder
		 */
		public Builder credentialsNonExpired(boolean credentialsNonExpired) {
			this.credentialsNonExpired = credentialsNonExpired;
			return this;
		}

		/**
		 * Builds the user.
		 * @return a new immutable {@link SecurityUser}
		 * @throws NullPointerException if the username is {@code null}
		 * @throws IllegalArgumentException if the username is blank
		 */
		public SecurityUser build() {
			return new SecurityUser(this.username, this.roles, this.permissions, this.enabled, this.accountNonExpired,
					this.accountNonLocked, this.credentialsNonExpired);
		}

	}

}
