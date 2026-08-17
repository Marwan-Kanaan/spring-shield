package io.github.marwankanaan.springshield.autoconfigure;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Auto-configuration behaviour for {@link SpringShieldAutoConfiguration}.
 *
 * <p>
 * Covers the conditional paths that decide whether SpringShield contributes anything,
 * which is the part most likely to break silently when conditions are edited later.
 *
 * @author mkanaan
 */
class SpringShieldAutoConfigurationTests {

	private final ApplicationContextRunner runner = new ApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(SpringShieldAutoConfiguration.class));

	@Test
	@DisplayName("adding the starter is enough; no property is needed to switch SpringShield on")
	void shouldBeActiveByDefault() {
		this.runner.run((context) -> assertThat(context).hasSingleBean(SpringShieldProperties.class));
	}

	@Test
	void shouldBeActiveWhenExplicitlyEnabled() {
		this.runner.withPropertyValues("springshield.enabled=true")
			.run((context) -> assertThat(context).hasSingleBean(SpringShieldProperties.class));
	}

	@Test
	void shouldBackOffCompletelyWhenDisabled() {
		this.runner.withPropertyValues("springshield.enabled=false")
			.run((context) -> assertThat(context).doesNotHaveBean(SpringShieldProperties.class));
	}

	@Test
	@DisplayName("the auto-configuration is registered for discovery, not just present on the classpath")
	void shouldBeListedInTheAutoConfigurationImportsFile() {
		assertThat(getClass().getClassLoader()
			.getResource("META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports"))
			.as("AutoConfiguration.imports must exist, or Spring Boot will never apply this auto-configuration")
			.isNotNull();
	}

}
