package io.github.marwankanaan.springshield.autoconfigure;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Entry point for SpringShield's Spring Boot auto-configuration.
 *
 * <p>
 * It binds {@link SpringShieldProperties} and contributes the default
 * {@link PasswordEncoder}. The security filter chain lives in
 * {@link SpringShieldWebSecurityAutoConfiguration}, because it only applies to servlet
 * web applications, whereas password encoding is useful anywhere.
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

	/**
	 * Contributes the default {@link PasswordEncoder}.
	 *
	 * <p>
	 * Isolated in its own configuration class and guarded by {@link ConditionalOnClass},
	 * so that an application without Spring Security's crypto support on the classpath
	 * still gets the rest of SpringShield's configuration rather than a class-loading
	 * failure.
	 *
	 * @author mkanaan
	 */
	@Configuration(proxyBeanMethods = false)
	@ConditionalOnClass(PasswordEncoder.class)
	static class PasswordEncoderConfiguration {

		/**
		 * The password encoder used to store and check passwords.
		 *
		 * <p>
		 * This is Spring Security's {@code DelegatingPasswordEncoder}, obtained from
		 * {@link PasswordEncoderFactories}. SpringShield does not implement password
		 * hashing; it only chooses a sensible default and lets you replace it.
		 *
		 * <p>
		 * New passwords are hashed with <strong>bcrypt</strong>, and the stored value
		 * carries its algorithm as a prefix:
		 *
		 * <pre>
		 * {bcrypt}$2a$10$N9qo8uLOickgx2ZMRZoMye...
		 * </pre>
		 *
		 * <p>
		 * That prefix is the point of the delegating encoder. It lets an application move
		 * to a stronger algorithm later without invalidating existing passwords: old
		 * hashes keep verifying under their own prefix while new ones are written with
		 * the new algorithm. Hard-coding a single encoder makes that migration impossible
		 * without forcing every user to reset their password.
		 *
		 * <p>
		 * <strong>Worth knowing:</strong> a delegating encoder can still verify legacy
		 * formats, including {@code {noop}} plaintext and weak digests such as
		 * {@code {MD5}}. That is deliberate in Spring Security, so existing data can be
		 * migrated. It does mean a stored {@code {noop}password} would authenticate, so
		 * treat any such value in a real user store as something to migrate rather than
		 * something the encoder will protect you from. Nothing SpringShield writes ever
		 * uses those formats.
		 *
		 * <p>
		 * To use a different encoder, declare your own bean and this one backs off:
		 *
		 * <pre>
		 * &#64;Bean
		 * PasswordEncoder passwordEncoder() {
		 *     return new Argon2PasswordEncoder(16, 32, 1, 1 &lt;&lt; 14, 2);
		 * }
		 * </pre>
		 * @return the delegating password encoder
		 */
		@Bean
		@ConditionalOnMissingBean(PasswordEncoder.class)
		PasswordEncoder passwordEncoder() {
			return PasswordEncoderFactories.createDelegatingPasswordEncoder();
		}

	}

}
