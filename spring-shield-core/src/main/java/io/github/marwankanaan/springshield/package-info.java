/**
 * Public abstractions that application code is expected to use and implement.
 *
 * <p>
 * Everything in this module is public API. Types here should stay stable across releases,
 * because applications compile against them and implement them.
 *
 * <p>
 * The only compile dependency is {@code spring-security-core}, needed so
 * {@link RequiresPermission} and {@link RequiresRole} can be meta-annotated with Spring
 * Security's {@code @PreAuthorize}. That makes them real Spring Security annotations
 * enforced by Spring Security's own method authorization, rather than markers
 * SpringShield would have to interpret with authorization code of its own.
 *
 * <p>
 * Nothing else is pulled in. There is no Spring Boot, servlet, web, JPA or JDBC coupling
 * here, so the value objects stay usable from plain domain code and depending on these
 * abstractions never forces a persistence choice. The Spring Boot wiring lives in
 * {@code spring-shield-autoconfigure}; storage adapters live in their own modules.
 *
 * <p>
 * Two consequences worth knowing before contributing here:
 *
 * <ul>
 * <li>Adding a compile dependency to this module changes the dependency footprint of
 * every SpringShield user, so it needs an explicit architectural justification.</li>
 * <li>Renaming or removing a type here is a breaking change and follows the deprecation
 * policy rather than being edited directly.</li>
 * </ul>
 *
 * @author mkanaan
 */
package io.github.marwankanaan.springshield;
