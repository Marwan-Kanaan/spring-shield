package io.github.marwankanaan.springshield.autoconfigure;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Responds to an authenticated caller who lacks the required authority, with 403 and a
 * JSON body.
 *
 * <p>
 * Spring Security calls this when an {@code AccessDeniedException} reaches the filter
 * chain. The distinction from 401 matters and is worth stating plainly: 401 means "I do
 * not know who you are", 403 means "I know who you are, and you may not do this". Sending
 * 403 to an unauthenticated caller would tell them their credentials were accepted.
 *
 * <p>
 * The response uses the code {@code ACCESS_DENIED}. Callers should branch on that rather
 * than on the message, which may be reworded.
 *
 * <p>
 * The message is a fixed constant and never names the authority that was missing.
 * Reporting "requires invoice.approve" would let a caller map out the permission model by
 * probing endpoints.
 *
 * <p>
 * This class is internal.
 *
 * @author mkanaan
 */
class SpringShieldAccessDeniedHandler implements AccessDeniedHandler {

	static final String CODE = "ACCESS_DENIED";

	private static final String MESSAGE = "Access denied";

	private final SecurityErrorResponseWriter writer;

	SpringShieldAccessDeniedHandler(SecurityErrorResponseWriter writer) {
		this.writer = writer;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException {
		this.writer.write(request, response, HttpServletResponse.SC_FORBIDDEN, CODE, MESSAGE);
	}

}
