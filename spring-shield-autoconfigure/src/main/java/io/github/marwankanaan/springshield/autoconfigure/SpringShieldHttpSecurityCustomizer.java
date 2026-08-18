package io.github.marwankanaan.springshield.autoconfigure;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Lets an optional feature add itself to SpringShield's filter chain.
 *
 * <p>
 * SpringShield builds one chain. Features that are only sometimes present, such as JWT
 * bearer token support, cannot simply contribute a second chain: two chains would mean
 * the effective policy depended on which matched first. They also cannot be written
 * directly into the chain method, because that method must still compile when their
 * classes are absent.
 *
 * <p>
 * A customizer solves both. Each optional feature publishes one from its own
 * auto-configuration, guarded by its own conditions, and the chain applies whichever are
 * present.
 *
 * <p>
 * This is internal, not an application extension point. An application that wants to
 * shape the chain should declare its own {@code SecurityFilterChain}, which makes
 * SpringShield back off entirely and keeps the whole policy visible in one place rather
 * than assembled from fragments.
 *
 * @author mkanaan
 */
@FunctionalInterface
interface SpringShieldHttpSecurityCustomizer {

	/**
	 * Applies this feature's configuration to the chain being built.
	 *
	 * <p>
	 * Called after SpringShield's authorization rules and before the chain is built.
	 * @param http the builder being configured
	 */
	void customize(HttpSecurity http);

}
