package io.github.marwankanaan.springshield;

/**
 * A single thing a user is allowed to do, such as {@code invoice.read}.
 *
 * <p>
 * A permission answers "what may this user do?". A {@link SecurityRole} answers "what is
 * this user?". Roles are usually bundles of permissions: an {@code ADMIN} role might
 * carry {@code user.read}, {@code user.create} and {@code user.delete}. Applications
 * should authorize against permissions rather than roles wherever practical, because
 * permissions survive reorganizations of the role model.
 *
 * <p>
 * Create one with {@link #of(String)}:
 *
 * <pre>
 * SecurityPermission read = SecurityPermission.of("invoice.read");
 * </pre>
 *
 * <h2>Naming</h2>
 *
 * <p>
 * The recommended convention is {@code resource.action}, for example {@code user.read},
 * {@code user.delete} or {@code invoice.approve}. The convention is not enforced, so a
 * single word such as {@code audit} is accepted, but consistency makes permissions far
 * easier to audit.
 *
 * <p>
 * Do not encode the identifier of a specific business object into a permission, such as
 * {@code invoice.approve.12345}. That produces an unbounded number of authorities and
 * moves a data-level decision into the authority list. Object-level access belongs in an
 * authorization rule that inspects the object.
 *
 * <h2>Validation</h2>
 *
 * <p>
 * The value is trimmed and must not be blank, must not contain whitespace, and must not
 * contain {@code ,} or {@code ;}. Those characters are rejected because authority values
 * are commonly serialized into delimited strings, such as an OAuth2 {@code scope} claim,
 * where an embedded delimiter would split one permission into two.
 *
 * <p>
 * Comparison is case-sensitive: {@code invoice.read} and {@code Invoice.Read} are
 * different permissions.
 *
 * @param value the permission identifier, never blank
 */
public record SecurityPermission(String value) {

	/**
	 * Canonical constructor, which trims and validates the value.
	 * @throws NullPointerException if {@code value} is {@code null}
	 * @throws IllegalArgumentException if the value is blank, or contains whitespace,
	 * {@code ,} or {@code ;}
	 */
	public SecurityPermission {
		value = AuthorityNames.requireValid(value, "permission");
	}

	/**
	 * Creates a permission.
	 *
	 * <p>
	 * Preferred over the constructor because it reads better at call sites:
	 * {@code SecurityPermission.of("invoice.read")}.
	 * @param value the permission identifier, such as {@code invoice.read}
	 * @return the permission
	 * @throws NullPointerException if {@code value} is {@code null}
	 * @throws IllegalArgumentException if the value is not valid
	 */
	public static SecurityPermission of(String value) {
		return new SecurityPermission(value);
	}

	/**
	 * Returns the permission identifier, so a permission prints as {@code invoice.read}
	 * rather than {@code SecurityPermission[value=invoice.read]}.
	 *
	 * <p>
	 * This keeps log and error output readable. It is safe to log a permission: a
	 * permission name is not a credential.
	 * @return the permission identifier
	 */
	@Override
	public String toString() {
		return this.value;
	}

}
