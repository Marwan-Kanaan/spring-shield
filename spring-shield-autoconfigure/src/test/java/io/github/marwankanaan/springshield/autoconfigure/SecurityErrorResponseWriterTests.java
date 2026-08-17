package io.github.marwankanaan.springshield.autoconfigure;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Escaping behaviour of {@link SecurityErrorResponseWriter}.
 *
 * <p>
 * The request path is echoed into the response body and is entirely caller-controlled.
 * Spring Security's request firewall stops the worst of it before the chain runs, but
 * this writer must not depend on that: it is the last thing between an untrusted string
 * and the response body, so it is tested directly with input the firewall would never let
 * through.
 *
 * @author mkanaan
 */
class SecurityErrorResponseWriterTests {

	private final SecurityErrorResponseWriter writer = new SecurityErrorResponseWriter();

	private String write(String requestUri) throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/");
		request.setRequestURI(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();

		this.writer.write(request, response, 401, "UNAUTHENTICATED", "Authentication is required");

		return response.getContentAsString();
	}

	@Test
	void shouldWriteTheDocumentedFields() throws Exception {
		String body = write("/api/reports");

		assertThat(body).contains("\"status\":401")
			.contains("\"code\":\"UNAUTHENTICATED\"")
			.contains("\"path\":\"/api/reports\"")
			.contains("\"timestamp\":\"")
			.contains("\"message\":\"");
	}

	@Test
	void shouldSetAJsonContentType() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api");
		MockHttpServletResponse response = new MockHttpServletResponse();

		this.writer.write(request, response, 403, "ACCESS_DENIED", "Access denied");

		assertThat(response.getContentType()).contains("application/json");
		assertThat(response.getStatus()).isEqualTo(403);
	}

	/**
	 * The critical case. An unescaped quote would close the JSON string early and let the
	 * caller inject arbitrary fields into the response body.
	 */
	@Test
	@DisplayName("a quote in the path is escaped rather than closing the JSON string")
	void shouldEscapeADoubleQuoteInThePath() throws Exception {
		String body = write("/api/a\"b");

		assertThat(body).contains("\"path\":\"/api/a\\\"b\"");
	}

	/**
	 * A lone trailing backslash would escape the closing quote of the JSON string.
	 */
	@Test
	void shouldEscapeABackslashInThePath() throws Exception {
		String body = write("/api/a\\b");

		assertThat(body).contains("\"path\":\"/api/a\\\\b\"");
	}

	/**
	 * An injected field must appear as literal text inside the path value, not as a
	 * structural part of the document.
	 */
	@Test
	void shouldNotAllowAnInjectedFieldToBecomeRealJson() throws Exception {
		String body = write("/api/x\",\"code\":\"ADMIN");

		assertThat(body).containsOnlyOnce("\"code\":\"UNAUTHENTICATED\"");
		assertThat(body).doesNotContain("\"code\":\"ADMIN\"");
	}

	@ParameterizedTest
	@ValueSource(strings = { "\n", "\r", "\t" })
	void shouldEscapeControlCharactersThatWouldBreakTheJsonString(String control) throws Exception {
		String body = write("/api/a" + control + "b");

		assertThat(body).doesNotContain(control);
	}

	@Test
	void shouldEscapeLowControlCharactersAsUnicode() throws Exception {
		String body = write("/api/a\u0001b");

		assertThat(body).contains("\\u0001").doesNotContain("\u0001");
	}

	/**
	 * Escaped so the body cannot be read as markup by a client that ignores the JSON
	 * content type.
	 */
	@Test
	void shouldEscapeMarkupCharacters() throws Exception {
		String body = write("/api/<script>&");

		assertThat(body).doesNotContain("<script>").contains("\\u003c").contains("\\u0026");
	}

	@Test
	void shouldNotWriteTwiceWhenTheResponseIsAlreadyCommitted() throws Exception {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api");
		MockHttpServletResponse response = new MockHttpServletResponse();
		response.setCommitted(true);

		this.writer.write(request, response, 401, "UNAUTHENTICATED", "Authentication is required");

		assertThat(response.getContentAsString()).isEmpty();
	}

}
