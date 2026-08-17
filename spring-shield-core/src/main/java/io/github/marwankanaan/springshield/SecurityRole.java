package io.github.marwankanaan.springshield;

/**
 * A named role a user holds, such as {@code ADMIN}.
 *
 * <p>
 * A role answers "what is this user?", while a {@link SecurityPermission} answers "what
 * may this user do?". Roles are normally coarse groupings that carry a set of
 * permissions. Prefer authorizing against permissions: role checks scattered through an
 * application become hard to change when the role model is reorganized.
 *
 * <p>
 * Create one with {@link #of(String)}:
 *
 * <pre>
 * SecurityRole admin = SecurityRole.of("ADMIN");
 * </pre>
 *
 * <h2>The ROLE_ prefix</h2>
 *
 * <p>
 * Spring Security represents a role as a {@code GrantedAuthority} whose name is the role
 * prefixed with {@code ROLE_}, so the role {@code ADMIN} becomes the authority
 * {@code ROLE_ADMIN}. That prefix is a Spring Security storage detail, and SpringShield
 * adds it when converting a role into an authority.
 *
 * <p>
 * A {@code SecurityRole} therefore holds the <strong>bare</strong> name, {@code ADMIN}.
 * Passing {@code ROLE_ADMIN} is rejected rather than accepted, because storing it would
 * produce the authority {@code ROLE_ROLE_ADMIN}. That mistake does not fail loudly: every
 * check for {@code ROLE_ADMIN} would simply stop matching, and the user would quietly
 * lose access. Failing at construction turns a silent authorization bug into an
 * immediate, obvious error.
 *
 * <h2>Validation</h2>
 *
 * <p>
 * The value is trimmed and must not be blank, must not contain whitespace, must not
 * contain {@code ,} or {@code ;}, and must not start with {@code ROLE_}. Delimiters are
 * rejected because authority values are commonly serialized into delimited strings, where
 * an embedded delimiter would split one role into two.
 *
 * <p>
 * Comparison is case-sensitive: {@code ADMIN} and {@code admin} are different roles.
 * Uppercase is the usual convention.
 *
 * @param value the bare role name, never blank and never {@code ROLE_}-prefixed
 */
public record SecurityRole(String value) {

	/**
	 * The prefix Spring Security uses for role authorities. Applied when a role is
	 * converted to an authority, never stored in {@link #value()}.
	 */
	public static final String ROLE_PREFIX = "ROLE_";

	/**
	 * Canonical constructor, which trims and validates the value.
	 * @throws NullPointerException if {@code value} is {@code null}
	 * @throws IllegalArgumentException if the value is blank, contains whitespace,
	 * {@code ,} or {@code ;}, or starts with {@code ROLE_}
	 */
	public SecurityRole {
		value = AuthorityNames.requireValid(value, "role");
		if (value.startsWith(ROLE_PREFIX)) {
			throw new IllegalArgumentException(
					("role value must not start with '%s', because SpringShield adds that prefix when converting a "
							+ "role to a Spring Security authority; use '%s' instead of '%s'")
						.formatted(ROLE_PREFIX, value.substring(ROLE_PREFIX.length()), value));
		}
	}

	/**
	 * Creates a role from its bare name.
	 * @param value the bare role name, such as {@code ADMIN}, without the {@code ROLE_}
	 * prefix
	 * @return the role
	 * @throws NullPointerException if {@code value} is {@code null}
	 * @throws IllegalArgumentException if the value is not valid
	 */
	public static SecurityRole of(String value) {
		return new SecurityRole(value);
	}

	/**
	 * Returns this role as a Spring Security authority name, that is the bare name with
	 * {@code ROLE_} prepended.
	 *
	 * <p>
	 * {@code SecurityRole.of("ADMIN").asAuthority()} returns {@code "ROLE_ADMIN"}. Use
	 * this when handing a role to Spring Security; use {@link #value()} when showing it
	 * to a human.
	 * @return the authority name, never {@code null}
	 */
	public String asAuthority() {
		return ROLE_PREFIX + this.value;
	}

	/**
	 * Returns the bare role name, so a role prints as {@code ADMIN} rather than
	 * {@code SecurityRole[value=ADMIN]}.
	 *
	 * <p>
	 * It is safe to log a role: a role name is not a credential.
	 * @return the bare role name
	 */
	@Override
	public String toString() {
		return this.value;
	}

}
