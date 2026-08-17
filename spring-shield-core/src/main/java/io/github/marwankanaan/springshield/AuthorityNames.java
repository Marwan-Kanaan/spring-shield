package io.github.marwankanaan.springshield;

import java.util.Objects;

/**
 * Shared validation for the text of a {@link SecurityRole} or {@link SecurityPermission}.
 *
 * <p>
 * This class exists so both types enforce exactly the same rules. If the two ever
 * disagreed about what a valid authority looks like, a value could be accepted as a
 * permission but rejected as a role, which is the kind of inconsistency that produces
 * confusing authorization bugs.
 *
 * <p>
 * Package-private on purpose: it is an implementation detail, not public API.
 *
 * @author mkanaan
 */
final class AuthorityNames {

	/**
	 * Characters that are rejected inside an authority value.
	 *
	 * <p>
	 * This is a security control, not a style rule. Authority values are routinely
	 * serialized into delimited strings: OAuth2 separates scopes with spaces, and Spring
	 * Security's own {@code AuthorityUtils.commaSeparatedStringToAuthorityList} separates
	 * authorities with commas. A value containing a delimiter would split into two
	 * authorities when it round-trips through such a format, so {@code "invoice read"}
	 * could silently become the separate authorities {@code "invoice"} and {@code "read"}
	 * and grant access that was never intended.
	 *
	 * <p>
	 * Rejecting the delimiter at construction time makes that impossible to express.
	 */
	private static final String FORBIDDEN_CHARACTERS = ",;";

	private AuthorityNames() {
	}

	/**
	 * Validates and normalizes an authority value.
	 *
	 * <p>
	 * Surrounding whitespace is trimmed, because a trailing space from a configuration
	 * file or database column is a typo rather than a meaningful difference. Nothing else
	 * is changed. In particular the value is <strong>not</strong> lower-cased or
	 * upper-cased: comparison stays case-sensitive, matching Spring Security's own
	 * treatment of authorities. Normalizing case would make {@code user.read} and
	 * {@code USER.READ} interchangeable, which is a decision an application should make
	 * deliberately rather than inherit silently.
	 * @param value the raw value, may have surrounding whitespace
	 * @param type the type name used in error messages, such as {@code "permission"}
	 * @return the trimmed value
	 * @throws NullPointerException if {@code value} is {@code null}
	 * @throws IllegalArgumentException if the value is blank or contains whitespace or a
	 * forbidden delimiter
	 */
	static String requireValid(String value, String type) {
		Objects.requireNonNull(value, () -> "%s value must not be null".formatted(type));
		String trimmed = value.trim();
		if (trimmed.isEmpty()) {
			throw new IllegalArgumentException("%s value must not be blank".formatted(type));
		}
		for (int i = 0; i < trimmed.length(); i++) {
			char character = trimmed.charAt(i);
			if (Character.isWhitespace(character)) {
				throw new IllegalArgumentException(
						"%s value must not contain whitespace, but was '%s'".formatted(type, trimmed));
			}
			if (FORBIDDEN_CHARACTERS.indexOf(character) >= 0) {
				throw new IllegalArgumentException(
						"%s value must not contain '%s', because that character separates authorities, but was '%s'"
							.formatted(type, character, trimmed));
			}
		}
		return trimmed;
	}

}
