# Changelog

Notable changes to SpringShield.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
will follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it has a release.

## [Unreleased]

Nothing has been published. The public API may still change without notice, and there is no
migration path between snapshots.

### Added

- Deny-by-default request authorization. Every request needs authentication unless its path
  is listed in `springshield.web.public-endpoints`.
- Username and password authentication against an application's own user store, through
  `SecurityUserProvider`.
- JWT bearer token validation with issuer and audience checking, and mapping of token claims
  to authorities.
- Role-to-permission expansion through `SecurityPermissionProvider`, on both the username and
  password path and the JWT path.
- `@RequiresPermission` and `@RequiresRole`, meta-annotated with Spring Security's
  `@PreAuthorize` so they are enforced by its own method authorization.
- A consistent JSON error contract for 401 and 403, with stable `code` values.
- A `DelegatingPasswordEncoder` default, so stored passwords record their algorithm and can
  be migrated later.
- `spring-shield-test`, with `@WithSecurityUser` for running a test as a caller holding
  chosen roles and permissions.
- Configuration under `springshield.*`, validated at binding so a bad value stops startup
  rather than being silently ignored.

### Security

- Patterns that would expose the whole application, `/**` and `**`, are rejected in
  `public-endpoints` rather than accepted.
- Error responses never contain a stack trace, the exception message, the missing authority,
  or the query string.
- An unknown username and a wrong password are reported identically, so neither reveals which
  accounts exist.
- The audience check accepts a token matching **any** configured audience, rather than
  requiring all of them, which would have rejected every token.
- A user with no encoded password cannot be signed in with any password.
- Roles are read from a token only when the claim is named, so no claim is adopted by guess.

### Known limitations

- Nested claim paths, such as Keycloak's `realm_access.roles`, are not supported.
- Role expansion runs on every request for bearer tokens, because the token is converted
  afresh each time.
- OIDC login, and JPA and JDBC adapters, are not implemented.
- Rate limiting, replay protection, object-level authorization and multi-tenant isolation are
  out of scope; see the threat model.
