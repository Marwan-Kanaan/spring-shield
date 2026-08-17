package io.github.marwankanaan.springshield.autoconfigure;

import java.util.List;
import java.util.Set;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;

/**
 * Contributes SpringShield's default security filter chain.
 *
 * <p>
 * The chain denies by default: every request needs authentication unless its path is
 * listed in {@code springshield.web.public-endpoints}. It otherwise matches Spring Boot's
 * own default chain, keeping form login and HTTP Basic, so adopting SpringShield adds the
 * public endpoint list without taking away a way to sign in.
 *
 * <p>
 * This class is internal and not a supported extension point.
 *
 * <h2>How this backs off</h2>
 *
 * <p>
 * An application that declares its own {@code SecurityFilterChain} bean keeps it: the
 * {@link ConditionalOnMissingBean} on {@link #springShieldSecurityFilterChain} means
 * SpringShield contributes nothing at all in that case, rather than adding a competing
 * chain.
 *
 * <p>
 * Spring Boot's default chain then withdraws by itself. Boot guards it with
 * {@code @ConditionalOnDefaultWebSecurity}, which requires that no
 * {@code SecurityFilterChain} bean is present, so whichever chain is contributed here
 * suppresses Boot's without SpringShield having to exclude or disable any Boot
 * auto-configuration.
 *
 * <p>
 * The three cases resolve as:
 *
 * <pre>
 * application declares a chain -&gt; the application's chain, SpringShield silent
 * only SpringShield present    -&gt; SpringShield's chain, Boot silent
 * springshield.enabled=false   -&gt; Spring Boot's default chain
 * </pre>
 *
 * <p>
 * Note the third case: disabling SpringShield does not disable security. Boot's own chain
 * takes over, so the application stays protected rather than becoming open.
 *
 * <h2>Why the ordering matters</h2>
 *
 * <p>
 * This auto-configuration is applied <strong>before</strong>
 * {@link ServletWebSecurityAutoConfiguration}. That is required, not cosmetic. Boot's
 * condition is evaluated when bean definitions are registered, so if Boot ran first it
 * would see no {@code SecurityFilterChain}, register its own, and the application would
 * end up with two chains. Only the first chain matched would apply, making the effective
 * security policy depend on bean ordering.
 *
 * @author mkanaan
 */
@AutoConfiguration(after = SpringShieldAutoConfiguration.class, before = ServletWebSecurityAutoConfiguration.class)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnClass({ SecurityFilterChain.class, HttpSecurity.class })
@ConditionalOnProperty(prefix = "springshield", name = "enabled", havingValue = "true", matchIfMissing = true)
public class SpringShieldWebSecurityAutoConfiguration {

	/**
	 * Creates the auto-configuration. Spring calls this; application code should not.
	 */
	public SpringShieldWebSecurityAutoConfiguration() {
	}

	/**
	 * Builds the default filter chain.
	 *
	 * <p>
	 * Rule order is significant. Spring Security evaluates authorization rules in the
	 * order they are declared and stops at the first match, so the public endpoints are
	 * registered before {@code anyRequest().authenticated()}. Declaring them the other
	 * way round would make {@code anyRequest()} match everything first and the public
	 * endpoints would never be reached.
	 *
	 * <p>
	 * CSRF protection, security headers and session handling are left at Spring
	 * Security's defaults. SpringShield does not weaken them.
	 * <p>
	 * Note there is no {@code throws Exception} here. Spring Security 7 removed the
	 * checked exception from its builder API, so the older idiom seen in most examples is
	 * no longer needed.
	 * @param http the builder Spring Security provides
	 * @param properties the bound {@code springshield} configuration
	 * @return the filter chain
	 */
	@Bean
	@ConditionalOnMissingBean(SecurityFilterChain.class)
	SecurityFilterChain springShieldSecurityFilterChain(HttpSecurity http, SpringShieldProperties properties) {
		List<String> publicEndpoints = properties.web().publicEndpoints();
		http.authorizeHttpRequests((requests) -> {
			if (!publicEndpoints.isEmpty()) {
				requests.requestMatchers(publicEndpoints.toArray(String[]::new)).permitAll();
			}
			requests.anyRequest().authenticated();
		});
		http.formLogin(Customizer.withDefaults());
		http.httpBasic(Customizer.withDefaults());
		applyErrorContract(http);
		return http.build();
	}

	/**
	 * Installs SpringShield's JSON responses for 401 and 403.
	 *
	 * <p>
	 * The 401 handler is registered only for callers that do not ask for HTML. A browser
	 * navigating to a protected page still gets Spring Security's redirect to the login
	 * form, because answering a navigation with a JSON body would leave the user staring
	 * at raw text. Everything else, which is every API client, gets the JSON contract.
	 *
	 * <p>
	 * The 403 handler applies to all callers. By the time access is denied the caller is
	 * already authenticated, so there is no login page to send them to.
	 * @param http the builder to configure
	 */
	private static void applyErrorContract(HttpSecurity http) {
		SecurityErrorResponseWriter writer = new SecurityErrorResponseWriter();
		MediaTypeRequestMatcher htmlMatcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		// A client sending Accept: */* is not asking for HTML in any meaningful sense, so
		// it
		// must not be treated as a browser navigation.
		htmlMatcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));
		http.exceptionHandling((handling) -> handling
			.defaultAuthenticationEntryPointFor(new SpringShieldAuthenticationEntryPoint(writer),
					new NegatedRequestMatcher(htmlMatcher))
			.accessDeniedHandler(new SpringShieldAccessDeniedHandler(writer)));
	}

}
