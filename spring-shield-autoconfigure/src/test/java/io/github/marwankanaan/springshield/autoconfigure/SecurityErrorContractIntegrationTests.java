package io.github.marwankanaan.springshield.autoconfigure;

import io.github.marwankanaan.springshield.RequiresPermission;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The security error contract, exercised through real requests.
 *
 * <p>
 * These check both halves of the promise: that the response is the documented shape, and
 * that it gives away nothing about why the request failed.
 *
 * @author mkanaan
 */
@SpringBootTest(classes = { SecurityErrorContractIntegrationTests.TestApplication.class,
		SecurityErrorContractIntegrationTests.ReportController.class })
@AutoConfigureMockMvc
class SecurityErrorContractIntegrationTests {

	@Autowired
	private MockMvc mvc;

	@Test
	@DisplayName("an unauthenticated API request gets 401 with the documented body")
	void shouldReturnTheDocumentedBodyForAnUnauthenticatedRequest() throws Exception {
		this.mvc.perform(get("/api/reports").header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE))
			.andExpect(status().isUnauthorized())
			.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
			.andExpect(jsonPath("$.status").value(401))
			.andExpect(jsonPath("$.code").value("UNAUTHENTICATED"))
			.andExpect(jsonPath("$.path").value("/api/reports"))
			.andExpect(jsonPath("$.timestamp").exists())
			.andExpect(jsonPath("$.message").exists());
	}

	@Test
	@WithMockUser(authorities = "report.read")
	@DisplayName("an authenticated caller lacking the authority gets 403, not 401")
	void shouldReturnTheDocumentedBodyForADeniedRequest() throws Exception {
		this.mvc.perform(get("/api/reports/export").header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE))
			.andExpect(status().isForbidden())
			.andExpect(jsonPath("$.status").value(403))
			.andExpect(jsonPath("$.code").value("ACCESS_DENIED"))
			.andExpect(jsonPath("$.path").value("/api/reports/export"));
	}

	/**
	 * A stack trace in a security response is the most useful thing an attacker can be
	 * handed, so the body must never contain one regardless of how the rest of the
	 * application is configured to report errors.
	 */
	@Test
	void shouldNeverIncludeAStackTraceOrExceptionType() throws Exception {
		String body = this.mvc.perform(get("/api/reports").header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE))
			.andReturn()
			.getResponse()
			.getContentAsString();

		org.assertj.core.api.Assertions.assertThat(body)
			.doesNotContain("Exception")
			.doesNotContain("org.springframework")
			.doesNotContain("at ")
			.doesNotContain("trace");
	}

	/**
	 * Reporting which authority was missing would let a caller map the permission model
	 * by probing endpoints until the message changed.
	 */
	@Test
	@WithMockUser(authorities = "report.read")
	void shouldNotNameTheMissingAuthority() throws Exception {
		String body = this.mvc.perform(get("/api/reports/export")).andReturn().getResponse().getContentAsString();

		org.assertj.core.api.Assertions.assertThat(body).doesNotContain("report.export");
	}

	/**
	 * The path is echoed straight from the request, so a caller controls it. A quote must
	 * not be able to break out of the JSON string.
	 */
	@Test
	void shouldEscapeAQuoteInThePathRatherThanEmitBrokenJson() throws Exception {
		this.mvc.perform(get("/api/{segment}", "a\"b").header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code").value("UNAUTHENTICATED"))
			.andExpect(jsonPath("$.status").value(401));
	}

	/**
	 * Defence in depth ahead of this contract: Spring Security's request firewall rejects
	 * a backslash in the path outright, so such a request never reaches the entry point
	 * at all. Recorded here because the safer-than-expected status is easy to mistake for
	 * a bug, and because a future change that relaxed the firewall should be noticed.
	 */
	@Test
	@DisplayName("a backslash in the path is rejected by the request firewall before the chain")
	void shouldRejectAPathContainingABackslashOutright() throws Exception {
		this.mvc.perform(get("/api/{segment}", "a\\b").header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE))
			.andExpect(status().isBadRequest());
	}

	/**
	 * A browser navigating to a protected page should reach the login form, not a JSON
	 * body it cannot render.
	 */
	@Test
	@DisplayName("a browser navigation still gets the login redirect, not JSON")
	void shouldRedirectABrowserNavigationToTheLoginForm() throws Exception {
		this.mvc.perform(get("/api/reports").header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE))
			.andExpect(status().is3xxRedirection());
	}

	/**
	 * Application under test.
	 *
	 * @author mkanaan
	 */
	@SpringBootApplication
	static class TestApplication {

	}

	/**
	 * Endpoints covering the unauthenticated and denied cases.
	 *
	 * @author mkanaan
	 */
	@RestController
	static class ReportController {

		@GetMapping("/api/reports")
		String reports() {
			return "reports";
		}

		@GetMapping("/api/reports/export")
		@RequiresPermission("report.export")
		String export() {
			return "exported";
		}

	}

}
