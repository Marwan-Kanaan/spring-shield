/**
 * Spring Boot auto-configuration that wires SpringShield into an application.
 *
 * <p>
 * These classes are internal. They are public only because Spring needs to instantiate
 * them, and they are not a supported extension point: they can be renamed or restructured
 * in any release. Extend SpringShield through the interfaces in
 * {@code io.github.marwankanaan.springshield} or by defining your own beans instead.
 *
 * <p>
 * Auto-configurations are discovered through
 * {@code META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}.
 * This module never component-scans, so adding a class here has no effect until it is
 * listed in that file.
 *
 * <h2>Backing off</h2>
 *
 * <p>
 * The rule is that an explicit application bean always wins. Every default SpringShield
 * contributes is guarded by {@code @ConditionalOnMissingBean}, so an application that
 * declares its own {@code SecurityFilterChain} or {@code PasswordEncoder} keeps it.
 *
 * <p>
 * This composes with Spring Boot's own behaviour rather than fighting it. Boot's default
 * chain is guarded by {@code @ConditionalOnDefaultWebSecurity}, which in Spring Boot 4.1
 * requires no {@code SecurityFilterChain} bean to be present. So when SpringShield
 * contributes a chain, Boot's default chain withdraws on its own, and the three cases
 * stack predictably:
 *
 * <pre>
 * application defines a chain  -&gt; the application's chain is used
 * only SpringShield is present -&gt; SpringShield's chain is used
 * SpringShield disabled        -&gt; Spring Boot's default chain is used
 * </pre>
 *
 * <p>
 * Ordering matters for that to hold: SpringShield's auto-configuration must be applied
 * before Boot's security auto-configuration, so that Boot's condition observes the
 * SpringShield chain.
 */
package io.github.marwankanaan.springshield.autoconfigure;
