package io.github.marwankanaan.springshield.autoconfigure;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end behaviour of the default filter chain, exercised with real HTTP requests.
 *
 * <p>
 * Asserting that a {@code SecurityFilterChain} bean exists proves nothing about whether
 * an unauthenticated request is actually rejected. These tests send requests through the
 * real chain, so the security policy itself is verified rather than its wiring.
 *
 * @author mkanaan
 */
@SpringBootTest(classes = DefaultSecurityFilterChainIntegrationTests.TestApplication.class,
		properties = { "springshield.web.public-endpoints[0]=/actuator/health",
				"springshield.web.public-endpoints[1]=/api/public/**" })
@AutoConfigureMockMvc
class DefaultSecurityFilterChainIntegrationTests {

	@Autowired
	private MockMvc mvc;

	@Test
	@DisplayName("a listed public endpoint is reachable without authentication")
	void shouldAllowAnonymousAccessToAConfiguredPublicEndpoint() throws Exception {
		this.mvc.perform(get("/actuator/health")).andExpect(status().isOk());
	}

	@Test
	void shouldAllowAnonymousAccessToAPathMatchingAPublicWildcard() throws Exception {
		this.mvc.perform(get("/api/public/info")).andExpect(status().isOk());
	}

	/**
	 * Deny by default, the core promise of this chain: anything not named as public
	 * requires authentication.
	 */
	@Test
	void shouldRejectAnonymousAccessToAnEndpointThatIsNotPublic() throws Exception {
		this.mvc.perform(get("/api/private")).andExpect(status().isUnauthorized());
	}

	/**
	 * A path nobody configured at all must also be denied, not merely the ones someone
	 * remembered to protect.
	 */
	@Test
	void shouldRejectAnonymousAccessToAnUnknownPath() throws Exception {
		this.mvc.perform(get("/anything/at/all")).andExpect(status().isUnauthorized());
	}

	@Test
	@WithMockUser
	void shouldAllowAnAuthenticatedUserThroughToAProtectedEndpoint() throws Exception {
		this.mvc.perform(get("/api/private")).andExpect(status().isOk());
	}

	/**
	 * CSRF protection is left at Spring Security's default. A state-changing request
	 * without a token must be rejected, which proves SpringShield has not quietly turned
	 * it off.
	 */
	@Test
	@WithMockUser
	void shouldRejectAStateChangingRequestWithoutACsrfToken() throws Exception {
		this.mvc.perform(post("/api/private")).andExpect(status().isForbidden());
	}

	@Test
	@WithMockUser
	void shouldAcceptAStateChangingRequestWithACsrfToken() throws Exception {
		this.mvc.perform(post("/api/private").with(csrf())).andExpect(status().isOk());
	}

	/**
	 * Minimal application under test.
	 *
	 * @author mkanaan
	 */
	@SpringBootApplication
	static class TestApplication {

		/**
		 * Endpoints covering the public, protected and state-changing cases.
		 *
		 * @author mkanaan
		 */
		@RestController
		static class TestController {

			@GetMapping("/actuator/health")
			String health() {
				return "ok";
			}

			@GetMapping("/api/public/info")
			String publicInfo() {
				return "public";
			}

			@GetMapping("/api/private")
			String privateResource() {
				return "private";
			}

			@PostMapping("/api/private")
			String createPrivateResource() {
				return "created";
			}

		}

	}

}
