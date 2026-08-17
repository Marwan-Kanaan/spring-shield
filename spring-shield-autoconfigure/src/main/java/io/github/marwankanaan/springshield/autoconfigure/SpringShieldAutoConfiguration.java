package io.github.marwankanaan.springshield.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Entry point for SpringShield's Spring Boot auto-configuration.
 *
 * <p>
 * At the moment this only binds {@link SpringShieldProperties}. Later work adds the
 * default security filter chain and the password encoder here.
 *
 * <p>
 * This class is internal. It is public only so Spring can instantiate it, and it is not a
 * supported extension point: do not import it, subclass it, or reference it from
 * application code.
 *
 * <h2>How it is discovered</h2>
 *
 * <p>
 * Through
 * {@code META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}.
 * SpringShield never component-scans, so a new class in this package does nothing until
 * it is listed in that file.
 *
 * <h2>Turning it off</h2>
 *
 * <p>
 * Setting {@code springshield.enabled=false} disables everything here, leaving the
 * application with Spring Boot's own security defaults. The property is absent by default
 * and treated as {@code true}, so simply adding the starter is enough to switch
 * SpringShield on.
 *
 * <p>
 * Note that disabling SpringShield does not disable security. Spring Boot's own security
 * auto-configuration still applies its default filter chain, so the application stays
 * protected rather than becoming open.
 *
 * @author mkanaan
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "springshield", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(SpringShieldProperties.class)
public class SpringShieldAutoConfiguration {

	/**
	 * Creates the auto-configuration. Spring calls this; application code should not.
	 */
	public SpringShieldAutoConfiguration() {
	}

}
