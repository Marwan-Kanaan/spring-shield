package io.github.marwankanaan.springshield.autoconfigure;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Conditional behaviour of {@link SpringShieldJwtAutoConfiguration}.
 *
 * <p>
 * A stub issuer stands in for a real identity provider, because the decoder fetches
 * issuer metadata while it is being built. Nothing here reaches the network.
 *
 * @author mkanaan
 */
class SpringShieldJwtAutoConfigurationTests {

	private StubIssuer issuer;

	private ApplicationContextRunner runner;

	@BeforeEach
	void startIssuer() throws Exception {
		this.issuer = StubIssuer.start();
		this.runner = new ApplicationContextRunner().withConfiguration(
				AutoConfigurations.of(SpringShieldAutoConfiguration.class, SpringShieldJwtAutoConfiguration.class));
	}

	@AfterEach
	void stopIssuer() {
		this.issuer.close();
	}

	private ApplicationContextRunner withIssuer() {
		return this.runner.withPropertyValues("springshield.jwt.issuer-uri=" + this.issuer.issuerUri());
	}

	@Test
	@DisplayName("setting the issuer is what switches JWT validation on")
	void shouldContributeADecoderWhenAnIssuerIsConfigured() {
		withIssuer().run((context) -> assertThat(context).hasSingleBean(JwtDecoder.class));
	}

	/**
	 * An application that never mentions an issuer must not gain bearer token handling by
	 * accident.
	 */
	@Test
	void shouldNotContributeADecoderWhenNoIssuerIsConfigured() {
		this.runner.run((context) -> assertThat(context).doesNotHaveBean(JwtDecoder.class));
	}

	@Test
	void shouldContributeTheChainCustomizerAlongsideTheDecoder() {
		withIssuer().run((context) -> assertThat(context).hasSingleBean(SpringShieldHttpSecurityCustomizer.class));
	}

	@Test
	void shouldBackOffWhenTheApplicationDeclaresItsOwnDecoder() {
		withIssuer().withUserConfiguration(CustomDecoderConfiguration.class).run((context) -> {
			assertThat(context).hasSingleBean(JwtDecoder.class);
			assertThat(context.getBean(JwtDecoder.class)).isInstanceOf(ApplicationJwtDecoder.class);
		});
	}

	/**
	 * Turning SpringShield off must turn JWT validation off with it, rather than leaving
	 * a half-configured context that fails to start.
	 */
	@Test
	void shouldNotContributeADecoderWhenSpringShieldIsDisabled() {
		withIssuer().withPropertyValues("springshield.enabled=false")
			.run((context) -> assertThat(context).doesNotHaveBean(JwtDecoder.class));
	}

	@Test
	void shouldBindConfiguredAudiences() {
		withIssuer()
			.withPropertyValues("springshield.jwt.audiences[0]=https://api.example.com",
					"springshield.jwt.audiences[1]=https://legacy.example.com")
			.run((context) -> assertThat(context.getBean(SpringShieldProperties.class).jwt().audiences())
				.containsExactly("https://api.example.com", "https://legacy.example.com"));
	}

	@Test
	void shouldDefaultToNoAudiences() {
		withIssuer()
			.run((context) -> assertThat(context.getBean(SpringShieldProperties.class).jwt().audiences()).isEmpty());
	}

	@Test
	void shouldRefuseToStartWhenTheIssuerIsBlank() {
		this.runner.withPropertyValues("springshield.jwt.issuer-uri=   ").run((context) -> {
			assertThat(context).hasFailed();
			assertThat(context).getFailure().hasStackTraceContaining("issuer-uri must not be blank");
		});
	}

	@Test
	void shouldRefuseToStartWhenAnAudienceIsBlank() {
		withIssuer().withPropertyValues("springshield.jwt.audiences[0]=   ").run((context) -> {
			assertThat(context).hasFailed();
			assertThat(context).getFailure().hasStackTraceContaining("must not contain a blank entry");
		});
	}

	/**
	 * Discovery happens while the decoder is built, so an unreachable issuer stops the
	 * application starting. That is fail-fast by design: a mistyped issuer is caught at
	 * deployment rather than surfacing later as rejected requests.
	 */
	@Test
	@DisplayName("an unreachable issuer fails startup rather than starting without validation")
	void shouldFailToStartWhenTheIssuerCannotBeReached() {
		this.runner.withPropertyValues("springshield.jwt.issuer-uri=http://127.0.0.1:1/unreachable").run((context) -> {
			assertThat(context).hasFailed();
			assertThat(context).getFailure().hasStackTraceContaining("Unable to resolve the Configuration");
		});
	}

	/**
	 * An application taking over decoding entirely.
	 *
	 * @author mkanaan
	 */
	@Configuration(proxyBeanMethods = false)
	static class CustomDecoderConfiguration {

		@Bean
		JwtDecoder jwtDecoder() {
			return new ApplicationJwtDecoder();
		}

	}

	/**
	 * Identifiable stand-in for an application-supplied decoder.
	 *
	 * @author mkanaan
	 */
	static class ApplicationJwtDecoder implements JwtDecoder {

		@Override
		public Jwt decode(String token) {
			throw new UnsupportedOperationException("not used in this test");
		}

	}

}
