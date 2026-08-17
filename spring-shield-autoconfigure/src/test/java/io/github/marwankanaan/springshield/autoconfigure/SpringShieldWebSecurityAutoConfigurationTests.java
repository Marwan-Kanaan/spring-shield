package io.github.marwankanaan.springshield.autoconfigure;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.security.autoconfigure.web.servlet.ServletWebSecurityAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Conditional behaviour of {@link SpringShieldWebSecurityAutoConfiguration}.
 *
 * <p>
 * These cover the back-off contract, which is the part of a starter most likely to break
 * silently: a mistake here does not throw, it just produces the wrong security policy.
 *
 * @author mkanaan
 */
class SpringShieldWebSecurityAutoConfigurationTests {

	private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(SpringShieldAutoConfiguration.class,
				SpringShieldWebSecurityAutoConfiguration.class, ServletWebSecurityAutoConfiguration.class));

	@Test
	void shouldContributeASecurityFilterChainByDefault() {
		this.runner.run((context) -> assertThat(context).hasSingleBean(SecurityFilterChain.class));
	}

	/**
	 * The most important guarantee this starter makes. An application that declares its
	 * own chain must keep it, and must not silently get a second one alongside.
	 */
	@Test
	void shouldBackOffEntirelyWhenTheApplicationDeclaresItsOwnChain() {
		this.runner.withUserConfiguration(CustomSecurityConfiguration.class).run((context) -> {
			assertThat(context).hasSingleBean(SecurityFilterChain.class);
			assertThat(context).hasBean("applicationSecurityFilterChain");
			assertThat(context).doesNotHaveBean("springShieldSecurityFilterChain");
		});
	}

	/**
	 * Guards the ordering. SpringShield is applied before Boot's security
	 * auto-configuration so that Boot's {@code @ConditionalOnDefaultWebSecurity} observes
	 * the SpringShield chain and withdraws. If that ordering were lost, both would
	 * register and the effective policy would depend on bean ordering.
	 */
	@Test
	@DisplayName("exactly one chain exists, so Spring Boot's default did not also register")
	void shouldSuppressSpringBootsDefaultChain() {
		this.runner.run((context) -> {
			assertThat(context).hasSingleBean(SecurityFilterChain.class);
			assertThat(context).hasBean("springShieldSecurityFilterChain");
			assertThat(context).doesNotHaveBean("defaultSecurityFilterChain");
		});
	}

	/**
	 * Disabling SpringShield must not disable security. Boot's own chain takes over, so
	 * the application stays protected rather than becoming open.
	 */
	@Test
	void shouldLeaveSpringBootsDefaultChainInPlaceWhenDisabled() {
		this.runner.withPropertyValues("springshield.enabled=false").run((context) -> {
			assertThat(context).doesNotHaveBean("springShieldSecurityFilterChain");
			assertThat(context).hasSingleBean(SecurityFilterChain.class);
		});
	}

	@Test
	void shouldNotContributeAChainToANonWebApplication() {
		new ApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(SpringShieldAutoConfiguration.class,
					SpringShieldWebSecurityAutoConfiguration.class))
			.run((context) -> assertThat(context).doesNotHaveBean(SecurityFilterChain.class));
	}

	@Test
	void shouldBuildTheChainWhenPublicEndpointsAreConfigured() {
		this.runner.withPropertyValues("springshield.web.public-endpoints[0]=/actuator/health")
			.run((context) -> assertThat(context).hasSingleBean(SecurityFilterChain.class));
	}

	/**
	 * A user-declared chain, standing in for an application that wants full control.
	 *
	 * @author mkanaan
	 */
	@Configuration(proxyBeanMethods = false)
	static class CustomSecurityConfiguration {

		@Bean
		SecurityFilterChain applicationSecurityFilterChain(HttpSecurity http) {
			http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
			http.httpBasic(Customizer.withDefaults());
			return http.build();
		}

	}

}
