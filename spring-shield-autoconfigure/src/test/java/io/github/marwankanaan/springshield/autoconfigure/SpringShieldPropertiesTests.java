package io.github.marwankanaan.springshield.autoconfigure;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Binding and validation tests for {@link SpringShieldProperties}.
 *
 * <p>
 * These run through a real application context rather than calling the constructor
 * directly, so they prove the properties actually bind from configuration the way an
 * application would supply them.
 *
 * @author mkanaan
 */
class SpringShieldPropertiesTests {

	private final ApplicationContextRunner runner = new ApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(SpringShieldAutoConfiguration.class));

	@Test
	void shouldBindPublicEndpointsInTheOrderTheyWereDeclared() {
		this.runner
			.withPropertyValues("springshield.web.public-endpoints[0]=/actuator/health",
					"springshield.web.public-endpoints[1]=/api/public/**")
			.run((context) -> assertThat(context.getBean(SpringShieldProperties.class).web().publicEndpoints())
				.containsExactly("/actuator/health", "/api/public/**"));
	}

	@Test
	@DisplayName("nothing is public unless it is named, so the default is an empty list")
	void shouldDefaultToNoPublicEndpoints() {
		this.runner.run((context) -> assertThat(context.getBean(SpringShieldProperties.class).web().publicEndpoints())
			.isEmpty());
	}

	@Test
	void shouldDefaultToEnabled() {
		this.runner.run((context) -> assertThat(context.getBean(SpringShieldProperties.class).enabled()).isTrue());
	}

	@Test
	void shouldSupplyADefaultWebSectionWhenItIsAbsent() {
		this.runner.run((context) -> assertThat(context.getBean(SpringShieldProperties.class).web()).isNotNull());
	}

	@Test
	void shouldTrimSurroundingWhitespaceOnAnEndpoint() {
		this.runner.withPropertyValues("springshield.web.public-endpoints[0]=  /actuator/health  ")
			.run((context) -> assertThat(context.getBean(SpringShieldProperties.class).web().publicEndpoints())
				.containsExactly("/actuator/health"));
	}

	@Test
	void shouldExposePublicEndpointsAsAnImmutableList() {
		this.runner.withPropertyValues("springshield.web.public-endpoints[0]=/health").run((context) -> {
			var endpoints = context.getBean(SpringShieldProperties.class).web().publicEndpoints();
			assertThat(endpoints.getClass().getName()).contains("Immutable");
		});
	}

	/**
	 * The most damaging thing this configuration can express. It is typically added
	 * during development and left behind, because nothing afterwards fails or looks
	 * wrong. Refusing to start is the only reliable way to surface it.
	 */
	@ParameterizedTest
	@ValueSource(strings = { "/**", "**" })
	void shouldRefuseToStartWhenAPatternWouldExposeEveryEndpoint(String pattern) {
		this.runner.withPropertyValues("springshield.web.public-endpoints[0]=" + pattern).run((context) -> {
			assertThat(context).hasFailed();
			assertThat(context).getFailure().hasStackTraceContaining("makes every endpoint");
			assertThat(context).getFailure().hasStackTraceContaining("SecurityFilterChain");
		});
	}

	/**
	 * A pattern without a leading slash never matches a request path, so the endpoint the
	 * author meant to open would silently stay protected. Failing loudly beats a
	 * configuration that quietly does nothing.
	 */
	@Test
	void shouldRefuseToStartWhenAPatternDoesNotStartWithASlash() {
		this.runner.withPropertyValues("springshield.web.public-endpoints[0]=actuator/health").run((context) -> {
			assertThat(context).hasFailed();
			assertThat(context).getFailure().hasStackTraceContaining("must start with '/'");
		});
	}

	/**
	 * Usually a missing list separator, which would silently leave the intended path
	 * protected.
	 */
	@Test
	void shouldRefuseToStartWhenAPatternContainsWhitespace() {
		this.runner.withPropertyValues("springshield.web.public-endpoints[0]=/api/a /api/b").run((context) -> {
			assertThat(context).hasFailed();
			assertThat(context).getFailure().hasStackTraceContaining("must not contain whitespace");
		});
	}

	@Test
	void shouldRefuseToStartWhenAPatternIsBlank() {
		this.runner.withPropertyValues("springshield.web.public-endpoints[0]=   ").run((context) -> {
			assertThat(context).hasFailed();
			assertThat(context).getFailure().hasStackTraceContaining("must not contain a blank entry");
		});
	}

	@Test
	@DisplayName("a valid catch-all-looking pattern that is not actually catch-all is still allowed")
	void shouldAllowABroadButScopedPattern() {
		this.runner.withPropertyValues("springshield.web.public-endpoints[0]=/api/public/**")
			.run((context) -> assertThat(context.getBean(SpringShieldProperties.class).web().publicEndpoints())
				.containsExactly("/api/public/**"));
	}

}
