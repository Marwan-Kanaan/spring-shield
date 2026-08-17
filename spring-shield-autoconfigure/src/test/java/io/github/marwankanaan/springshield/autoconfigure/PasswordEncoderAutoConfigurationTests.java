package io.github.marwankanaan.springshield.autoconfigure;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Behaviour of the default {@link PasswordEncoder}.
 *
 * <p>
 * These assert what the encoder actually produces rather than only that a bean exists. A
 * misconfigured encoder still satisfies "a PasswordEncoder bean is present" while storing
 * passwords in a form that offers no protection.
 *
 * @author mkanaan
 */
class PasswordEncoderAutoConfigurationTests {

	private static final String PASSWORD = "correct horse battery staple";

	private final ApplicationContextRunner runner = new ApplicationContextRunner()
		.withConfiguration(AutoConfigurations.of(SpringShieldAutoConfiguration.class));

	@Test
	void shouldContributeADelegatingPasswordEncoderByDefault() {
		this.runner.run((context) -> {
			assertThat(context).hasSingleBean(PasswordEncoder.class);
			assertThat(context.getBean(PasswordEncoder.class)).isInstanceOf(DelegatingPasswordEncoder.class);
		});
	}

	/**
	 * The stored value must carry its algorithm as a prefix. Without it, moving to a
	 * stronger algorithm later means invalidating every existing password.
	 */
	@Test
	void shouldEncodeNewPasswordsWithBcryptAndRecordTheAlgorithm() {
		this.runner.run((context) -> assertThat(context.getBean(PasswordEncoder.class).encode(PASSWORD))
			.startsWith("{bcrypt}$2"));
	}

	/**
	 * The single most important property: the raw password must never survive encoding.
	 */
	@Test
	@DisplayName("the encoded value never contains the plaintext password")
	void shouldNeverStoreThePasswordInRecoverableForm() {
		this.runner.run((context) -> {
			String encoded = context.getBean(PasswordEncoder.class).encode(PASSWORD);

			assertThat(encoded).isNotEqualTo(PASSWORD).doesNotContain(PASSWORD);
		});
	}

	/**
	 * Guards against a plaintext encoder being used as a convenience default. A
	 * {@code {noop}} prefix here would mean passwords are stored exactly as typed.
	 */
	@Test
	void shouldNotUseAPlaintextEncoderByDefault() {
		this.runner.run((context) -> assertThat(context.getBean(PasswordEncoder.class).encode(PASSWORD))
			.doesNotStartWith("{noop}"));
	}

	/**
	 * bcrypt salts every hash, so the same password encoded twice must differ. Identical
	 * output would mean an unsalted digest, which lets an attacker with the password
	 * database identify users who share a password and attack them with rainbow tables.
	 */
	@Test
	void shouldProduceADifferentHashEachTimeBecauseTheEncoderSalts() {
		this.runner.run((context) -> {
			PasswordEncoder encoder = context.getBean(PasswordEncoder.class);

			assertThat(encoder.encode(PASSWORD)).isNotEqualTo(encoder.encode(PASSWORD));
		});
	}

	@Test
	void shouldMatchAPasswordAgainstItsOwnHash() {
		this.runner.run((context) -> {
			PasswordEncoder encoder = context.getBean(PasswordEncoder.class);

			assertThat(encoder.matches(PASSWORD, encoder.encode(PASSWORD))).isTrue();
		});
	}

	@Test
	void shouldNotMatchAWrongPassword() {
		this.runner.run((context) -> {
			PasswordEncoder encoder = context.getBean(PasswordEncoder.class);

			assertThat(encoder.matches("wrong password", encoder.encode(PASSWORD))).isFalse();
		});
	}

	@Test
	void shouldBackOffWhenTheApplicationDeclaresItsOwnEncoder() {
		this.runner.withUserConfiguration(CustomPasswordEncoderConfiguration.class).run((context) -> {
			assertThat(context).hasSingleBean(PasswordEncoder.class);
			assertThat(context.getBean(PasswordEncoder.class)).isInstanceOf(BCryptPasswordEncoder.class);
		});
	}

	@Test
	void shouldNotContributeAnEncoderWhenSpringShieldIsDisabled() {
		this.runner.withPropertyValues("springshield.enabled=false")
			.run((context) -> assertThat(context).doesNotHaveBean(PasswordEncoder.class));
	}

	/**
	 * An application choosing its own encoder, standing in for a deliberate policy
	 * decision.
	 *
	 * @author mkanaan
	 */
	@Configuration(proxyBeanMethods = false)
	static class CustomPasswordEncoderConfiguration {

		@Bean
		PasswordEncoder passwordEncoder() {
			return new BCryptPasswordEncoder();
		}

	}

}
