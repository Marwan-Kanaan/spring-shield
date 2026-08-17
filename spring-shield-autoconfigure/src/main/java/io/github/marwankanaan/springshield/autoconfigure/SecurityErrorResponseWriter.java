package io.github.marwankanaan.springshield.autoconfigure;

import java.io.IOException;
import java.time.Instant;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Writes SpringShield's security error responses as JSON.
 *
 * <p>
 * Shared by the authentication entry point and the access denied handler so both produce
 * the same shape:
 *
 * <pre>
 * {
 *   "timestamp": "2026-08-17T12:30:00Z",
 *   "status": 403,
 *   "code": "ACCESS_DENIED",
 *   "message": "Access denied",
 *   "path": "/api/invoices"
 * }
 * </pre>
 *
 * <p>
 * {@code code} is the field to branch on. It is a stable identifier that will not change
 * with wording, unlike {@code message}, which is meant for humans reading logs.
 *
 * <h2>What is deliberately left out</h2>
 *
 * <p>
 * Three omissions, each of them a decision rather than an oversight:
 *
 * <ul>
 * <li><strong>No exception message.</strong> The messages are fixed constants rather than
 * anything taken from the thrown exception. An exception message can name internal types,
 * expressions or configuration, and repeating it to an unauthenticated caller hands out
 * detail about the system for free.</li>
 * <li><strong>No stack trace, ever.</strong> Not even when
 * {@code server.error.include-stacktrace} is enabled for the rest of the application. A
 * security failure is precisely where a stack trace is most useful to an attacker.</li>
 * <li><strong>No query string.</strong> Only the request path is echoed. Query strings
 * routinely carry tokens, keys and identifiers, and reflecting them into a response body
 * puts them somewhere they are likely to be logged or cached.</li>
 * </ul>
 *
 * <p>
 * This class is internal.
 *
 * @author mkanaan
 */
final class SecurityErrorResponseWriter {

	private static final String CONTENT_TYPE = "application/json;charset=UTF-8";

	/**
	 * Writes the error response.
	 *
	 * <p>
	 * Does nothing if the response is already committed, which can happen if something
	 * earlier in the chain has started writing. Attempting to write again would throw and
	 * mask the original failure.
	 * @param request the request that was rejected, used only for its path
	 * @param response the response to write to
	 * @param status the HTTP status to send
	 * @param code the stable error code, such as {@code ACCESS_DENIED}
	 * @param message a fixed human-readable message, never taken from an exception
	 * @throws IOException if the response cannot be written
	 */
	void write(HttpServletRequest request, HttpServletResponse response, int status, String code, String message)
			throws IOException {
		if (response.isCommitted()) {
			return;
		}
		response.setStatus(status);
		response.setContentType(CONTENT_TYPE);
		StringBuilder json = new StringBuilder(160);
		json.append("{\"timestamp\":\"").append(Instant.now()).append('"');
		json.append(",\"status\":").append(status);
		json.append(",\"code\":\"");
		appendEscaped(json, code);
		json.append("\",\"message\":\"");
		appendEscaped(json, message);
		json.append("\",\"path\":\"");
		appendEscaped(json, request.getRequestURI());
		json.append("\"}");
		response.getWriter().write(json.toString());
	}

	/**
	 * Appends a string as an escaped JSON string body.
	 *
	 * <p>
	 * The request path reaches this method straight from the caller, so it is untrusted.
	 * A path containing a quote or a backslash would otherwise break out of the JSON
	 * string and let the caller shape the response body.
	 *
	 * <p>
	 * {@code <}, {@code >} and {@code &} are escaped as well. They are legal in JSON and
	 * not strictly required to be escaped, but escaping them means the body cannot be
	 * read as markup by a client that ignores the content type.
	 * @param out the buffer to append to
	 * @param value the untrusted value
	 */
	private static void appendEscaped(StringBuilder out, String value) {
		if (value == null) {
			return;
		}
		for (int i = 0; i < value.length(); i++) {
			char character = value.charAt(i);
			switch (character) {
				case '"' -> out.append("\\\"");
				case '\\' -> out.append("\\\\");
				case '\n' -> out.append("\\n");
				case '\r' -> out.append("\\r");
				case '\t' -> out.append("\\t");
				case '\b' -> out.append("\\b");
				case '\f' -> out.append("\\f");
				case '<', '>', '&' -> appendUnicodeEscape(out, character);
				default -> {
					if (character < 0x20) {
						appendUnicodeEscape(out, character);
					}
					else {
						out.append(character);
					}
				}
			}
		}
	}

	private static void appendUnicodeEscape(StringBuilder out, char character) {
		out.append("\\u").append(String.format("%04x", (int) character));
	}

}
