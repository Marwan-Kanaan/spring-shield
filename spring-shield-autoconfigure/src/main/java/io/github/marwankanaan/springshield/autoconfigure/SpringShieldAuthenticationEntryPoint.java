package io.github.marwankanaan.springshield.autoconfigure;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Responds to a request that needs authentication but does not have it, with 401 and a
 * JSON body.
 *
 * <p>
 * Spring Security calls this when an {@code AuthenticationException} reaches the filter
 * chain, which in practice means the caller sent no credentials, or credentials that were
 * not accepted.
 *
 * <p>
 * The response uses the code {@code UNAUTHENTICATED}. Callers should branch on that
 * rather than on the message, which may be reworded.
 *
 * <p>
 * The message is a fixed constant and never repeats the {@code AuthenticationException}.
 * A failure reason such as "user not found" or "credentials expired" would tell an
 * unauthenticated caller which usernames exist and what state they are in, which is
 * exactly the enumeration signal Spring Security works to hide.
 *
 * <p>
 * This class is internal.
 *
 * @author mkanaan
 */
class SpringShieldAuthenticationEntryPoint implements AuthenticationEntryPoint {

	static final String CODE = "UNAUTHENTICATED";

	private static final String MESSAGE = "Authentication is required to access this resource";

	private final SecurityErrorResponseWriter writer;

	private final String basicRealm;

	SpringShieldAuthenticationEntryPoint(SecurityErrorResponseWriter writer) {
		this(writer, null);
	}

	/**
	 * Creates an entry point that also issues an HTTP Basic challenge.
	 *
	 * <p>
	 * Used for the HTTP Basic path, where a failed sign-in would otherwise return a bare
	 * 401 with no body: {@code httpBasic()} installs its own entry point, which never
	 * reaches the one configured for the rest of the chain. Without this, "no
	 * credentials" would answer with the documented JSON while "wrong credentials"
	 * answered with something else.
	 *
	 * <p>
	 * The {@code WWW-Authenticate} header is kept because it is what tells a client which
	 * scheme to use, and dropping it in favour of a nicer body would break HTTP Basic for
	 * anything that relies on the challenge.
	 * @param writer writes the JSON body
	 * @param basicRealm realm to advertise, or {@code null} to send no challenge
	 */
	SpringShieldAuthenticationEntryPoint(SecurityErrorResponseWriter writer, String basicRealm) {
		this.writer = writer;
		this.basicRealm = basicRealm;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authenticationException) throws IOException {
		if (this.basicRealm != null && !response.isCommitted()) {
			response.setHeader("WWW-Authenticate", "Basic realm=\"" + this.basicRealm + "\"");
		}
		this.writer.write(request, response, HttpServletResponse.SC_UNAUTHORIZED, CODE, MESSAGE);
	}

}
