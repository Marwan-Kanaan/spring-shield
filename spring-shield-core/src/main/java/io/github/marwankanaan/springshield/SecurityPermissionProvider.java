package io.github.marwankanaan.springshield;

import java.util.Set;

/**
 * Expands roles into the permissions they grant.
 *
 * <p>
 * Most applications store coarse roles against a user and define separately what each
 * role allows. This is the hook for that second part: given the roles a caller holds,
 * return the permissions those roles carry.
 *
 * <pre>
 * &#64;Component
 * class JdbcSecurityPermissionProvider implements SecurityPermissionProvider {
 *
 *     &#64;Override
 *     public Set&lt;SecurityPermission&gt; findPermissions(Set&lt;SecurityRole&gt; roles) {
 *         return this.rolePermissions.findByRoleNames(roles.stream().map(SecurityRole::value).toList());
 *     }
 *
 * }
 * </pre>
 *
 * <h2>Why this is separate from SecurityUserProvider</h2>
 *
 * <p>
 * A {@link SecurityUser} already carries permissions, so for username and password
 * authentication a provider can simply populate them and never implement this interface.
 *
 * <p>
 * It exists for the JWT and OIDC case, where there is no user lookup at all. There the
 * identity and usually the roles arrive inside a validated token, so no
 * {@link SecurityUserProvider} runs, and role-to-permission expansion still has to happen
 * somewhere. Without this hook a token-authenticated caller could only ever be authorized
 * by role, which loses the permission model entirely.
 *
 * <h2>Why it takes all roles at once</h2>
 *
 * <p>
 * The method deliberately accepts the whole role set rather than a single role. A
 * per-role method reads more naturally but is a trap: it turns one authorization decision
 * into one lookup per role, so a user with five roles causes five queries on a path that
 * runs on every request. Passing the full set lets an implementation answer with a single
 * query.
 *
 * <h2>Failure behaviour</h2>
 *
 * <p>
 * If permissions cannot be resolved, throw. Do not return an empty set to signal failure
 * and do not silently return a partial result. An empty set is indistinguishable from
 * "these roles legitimately grant nothing", so a database outage would look like a
 * successful answer and quietly strip a user's permissions. Throwing fails the request
 * instead, which is the safe outcome.
 *
 * <p>
 * Implementations are used as singletons and must be thread-safe.
 */
@FunctionalInterface
public interface SecurityPermissionProvider {

	/**
	 * Returns every permission granted by the given roles.
	 * @param roles the roles held by the caller, never {@code null}, possibly empty
	 * @return the permissions those roles grant, never {@code null}, possibly empty. The
	 * result is a union across all the roles, so a permission granted by two roles
	 * appears once.
	 */
	Set<SecurityPermission> findPermissions(Set<SecurityRole> roles);

	/**
	 * Returns a provider that grants no permissions at all, whatever roles it is given.
	 *
	 * <p>
	 * This is the safe default when an application has no role-to-permission mapping: it
	 * adds nothing, so authorization falls back to whatever permissions are already on
	 * the {@link SecurityUser}. It is also convenient in tests that only care about
	 * roles.
	 *
	 * <p>
	 * Granting nothing is deliberate. A default that guessed at permissions would hand
	 * out access the application never configured.
	 * @return a provider that always returns an empty set, never {@code null}
	 */
	static SecurityPermissionProvider none() {
		return roles -> Set.of();
	}

}
