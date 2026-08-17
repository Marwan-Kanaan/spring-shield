package io.github.marwankanaan.springshield;

import java.util.Optional;

/**
 * Looks a user up in the application's own user store.
 *
 * <p>
 * This is the main extension point for username and password authentication. Implement
 * it, publish it as a bean, and SpringShield will use it instead of any default:
 *
 * <pre>
 * &#64;Component
 * class JdbcSecurityUserProvider implements SecurityUserProvider {
 *
 *     &#64;Override
 *     public Optional&lt;SecurityUser&gt; findByUsername(String username) {
 *         return this.accounts.findByUsername(username)
 *             .map(account -&gt; SecurityUser.builder(account.username())
 *                 .roles(account.roles())
 *                 .enabled(account.isActive())
 *                 .accountNonLocked(!account.isLocked())
 *                 .build());
 *     }
 *
 * }
 * </pre>
 *
 * <p>
 * The interface is deliberately tiny, so a test can supply one as a lambda:
 * {@code username -> Optional.of(someUser)}.
 *
 * <h2>Return empty, do not throw</h2>
 *
 * <p>
 * When no user matches, return {@link Optional#empty()}. A missing user is an ordinary
 * outcome of a lookup, not an error, so it should not cost an exception.
 *
 * <p>
 * This also matters for security. SpringShield turns an empty result into the same
 * authentication failure that a wrong password produces, so a caller cannot tell the two
 * apart. Throwing your own exception, or returning a different error for an unknown user,
 * would reintroduce exactly the difference that lets an attacker enumerate valid
 * usernames.
 *
 * <p>
 * Spring Security handles the rest of that problem for you. Its
 * {@code DaoAuthenticationProvider} hides a "user not found" condition behind a generic
 * bad credentials failure by default, and it deliberately performs a dummy password check
 * when no user was found, so an unknown username takes about as long to reject as a known
 * one. Do not attempt to reimplement either behaviour.
 *
 * <h2>Implementation notes</h2>
 *
 * <ul>
 * <li>Do not log the supplied username at a level that would record which names exist,
 * and never log a password or token.</li>
 * <li>Return a fully populated {@link SecurityUser}. Resolve roles and any lazily-loaded
 * associations before returning, because the returned value is used on the authorization
 * path where no transaction may be open.</li>
 * <li>Implementations are used as singletons and must be thread-safe.</li>
 * <li>This is called on the authentication path, so keep it to a single efficient query
 * where possible.</li>
 * </ul>
 *
 * @author mkanaan
 */
@FunctionalInterface
public interface SecurityUserProvider {

	/**
	 * Finds the user with the given username.
	 * @param username the username being authenticated, never {@code null}
	 * @return the matching user, or {@link Optional#empty()} if there is none. Never
	 * {@code null}.
	 */
	Optional<SecurityUser> findByUsername(String username);

}
