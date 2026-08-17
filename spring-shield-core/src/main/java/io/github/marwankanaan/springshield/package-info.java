/**
 * Public abstractions that application code is expected to use and implement.
 *
 * <p>Everything in this module is public API. Types here should stay stable across
 * releases, because applications compile against them and implement them.
 *
 * <p>This module has no compile-scope dependencies, and that is deliberate. It carries no
 * Spring Boot, Spring Security, JPA or JDBC coupling, so depending on SpringShield's
 * abstractions never forces a persistence or framework choice on an application. The
 * Spring wiring lives in {@code spring-shield-autoconfigure}; storage adapters live in
 * their own modules.
 *
 * <p>Two consequences worth knowing before contributing here:
 *
 * <ul>
 *   <li>Adding a compile dependency to this module changes the dependency footprint of
 *       every SpringShield user, so it needs an explicit architectural justification.</li>
 *   <li>Renaming or removing a type here is a breaking change and follows the
 *       deprecation policy rather than being edited directly.</li>
 * </ul>
 */
package io.github.marwankanaan.springshield;
