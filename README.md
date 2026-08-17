# SpringShield

An opinionated, secure-by-default Spring Boot starter that orchestrates Spring Security.

> **Status: pre-alpha, nothing published yet.**
> Request authorization works: SpringShield contributes a filter chain that denies by
> default and permits the endpoints you list. What does **not** exist yet is authentication
> of its own (JWT and OIDC are planned, so users are still supplied the usual Spring
> Security way), permission-based authorization, and the `@RequiresPermission` annotations.
> The public API may still change without notice.

## What it is

SpringShield removes repetitive security configuration from Spring Boot applications
without replacing Spring Security.

It is a thin orchestration and developer-experience layer. Authentication, authorization,
password encoding, JWT validation and the filter chain remain Spring Security's job.
SpringShield's contribution is sensible defaults and a small set of extension points,
arranged so the secure path is also the easy one.

## What it is not

It is **not** a replacement for Spring Security, and not a second security engine beside
it. It does not implement its own cryptography, JWT verification, password hashing or
authentication protocols. Where Spring Security already solves a problem, SpringShield
delegates to it.

If SpringShield's defaults do not suit your application, you keep normal Spring Security:
declare your own beans and SpringShield gets out of the way.

## Baseline

| | Version |
|---|---|
| Java | 21 |
| Spring Boot | 4.1.0 |
| Spring Security | 7.1.0 (managed by Spring Boot) |
| Build | Maven 3.9+ |

Spring Security's version is inherited from Spring Boot's dependency management rather
than pinned independently, so the stack stays internally consistent and picks up Boot's
security patches.

## Modules

| Module | Role |
|---|---|
| `spring-shield-core` | Public abstractions and annotations. Depends only on `spring-security-core`, so it forces no Spring Boot, web or persistence choice. |
| `spring-shield-autoconfigure` | Spring Boot integration, configuration properties and default wiring. Internal. |
| `spring-shield-spring-boot-starter` | The dependency you add. Aggregator only, no logic. |

Optional integrations (JPA, JDBC, OAuth2/OIDC SSO) will live in separate modules so
applications that do not use them do not inherit their dependencies.

## Configuration

All settings live under the `springshield` namespace, are strongly typed, and ship IDE
completion metadata.

```yaml
springshield:
  enabled: true
  web:
    public-endpoints:
      - /actuator/health
      - /api/public/**
```

| Property | Default | Meaning |
|---|---|---|
| `springshield.enabled` | `true` | Whether SpringShield configures anything. When `false` it backs off entirely and Spring Boot's own security defaults apply, so the application stays protected rather than becoming open. |
| `springshield.web.public-endpoints` | *(empty)* | Request patterns reachable without authentication. Empty by default, so nothing is public until you name it. |
| `springshield.authorization.enabled` | `true` | Whether method security is on, which is what makes `@RequiresPermission` and `@RequiresRole` take effect. |

These are enforced. SpringShield contributes a `SecurityFilterChain` that permits the listed
patterns and requires authentication for everything else, verified by tests that issue real
requests through the chain.

What is **not** implemented yet is any authentication mechanism of SpringShield's own. The
chain keeps Spring Boot's form login and HTTP Basic, so you still need to supply users the
usual Spring Security way. JWT and OIDC come later.

### Configuration mistakes stop startup

Security settings fail loudly rather than being quietly ignored, because a setting that is
silently dropped is worse than one that refuses to start:

```yaml
springshield:
  web:
    public-endpoints:
      - /**            # rejected: would make every endpoint public
      - actuator/health # rejected: no leading slash, so it would never match
      - /api/a /api/b   # rejected: missing list separator
```

The `/**` rejection is deliberate. Opening every endpoint is usually added during
development and left behind, because nothing afterwards fails or looks wrong. An
application that genuinely needs no authentication should say so by declaring its own
`SecurityFilterChain`, where the intent is visible in code review.

### Planned

Not yet implemented, listed so the intended shape is clear: `springshield.authentication.mode`,
and the `springshield.jwt.*` block for issuer and audience validation.

## Backing off

The most important behaviour of a starter is what happens when the application wants
control. Every default SpringShield contributes is guarded by `@ConditionalOnMissingBean`,
so an explicit application bean always wins:

```java
@Bean
SecurityFilterChain applicationSecurity(HttpSecurity http) throws Exception {
    // SpringShield does not contribute a competing chain.
}
```

This composes with Spring Boot rather than fighting it. Boot's own default chain is
guarded by `@ConditionalOnDefaultWebSecurity`, which in Spring Boot 4.1 requires that no
`SecurityFilterChain` bean is present — so when SpringShield contributes one, Boot's
default withdraws on its own.

## Building

Requires JDK 21. Maven uses the JDK from `JAVA_HOME`, which may differ from whichever
`java` is first on your `PATH`.

```bash
mvn clean verify
```

## Method authorization

Guard a method with a permission or a role:

```java
@Service
class InvoiceService {

    @RequiresPermission("invoice.read")
    List<Invoice> findAll() { ... }

    @RequiresRole("ADMIN")
    void deleteAll() { ... }
}
```

A caller without it gets an `AccessDeniedException`, normally HTTP 403, and the method body
never runs.

**These are Spring Security annotations, not a parallel mechanism.** Each is meta-annotated
with `@PreAuthorize`, so `@RequiresPermission("invoice.read")` is exactly equivalent to
`@PreAuthorize("hasAuthority('invoice.read')")` and is enforced by the same method
authorization. They compose freely with `@PreAuthorize`, `@PostAuthorize` and a custom
`AuthorizationManager`.

Two limitations inherited from Spring proxies, both of which surprise people:

- **Self-invocation is not checked.** A method calling an annotated method on `this` does
  not pass through the proxy, so nothing is enforced.
- **Only Spring-managed beans are covered.** An object created with `new` is not proxied.

Write the **bare** role name — `@RequiresRole("ADMIN")`, never `"ROLE_ADMIN"`. Spring
Security adds the prefix when checking, so a prefixed value looks for `ROLE_ROLE_ADMIN` and
silently never matches.

Set `springshield.authorization.enabled=false` to switch method security off. Be careful:
that does not relax one rule, it stops all of these annotations being enforced, so a method
that still reads as guarded runs unguarded.

## Password encoding

SpringShield registers Spring Security's `DelegatingPasswordEncoder`. It does not implement
password hashing — it picks a sensible default and lets you replace it.

New passwords are hashed with **bcrypt**, and the stored value records its algorithm:

```text
{bcrypt}$2a$10$N9qo8uLOickgx2ZMRZoMye...
```

That prefix is the whole point: you can move to a stronger algorithm later without
invalidating existing passwords, because old hashes keep verifying under their own prefix
while new ones are written with the new algorithm.

Inject it wherever you create users:

```java
user.setPassword(passwordEncoder.encode(rawPassword));
```

Declaring your own bean makes SpringShield back off:

```java
@Bean
PasswordEncoder passwordEncoder() {
    return new Argon2PasswordEncoder(16, 32, 1, 1 << 14, 2);
}
```

> **Worth knowing:** a delegating encoder can still *verify* legacy formats, including
> `{noop}` plaintext and weak digests such as `{MD5}`. That is deliberate in Spring Security
> so existing data can be migrated, but it means a stored `{noop}password` will
> authenticate. Treat any such value in a real user store as something to migrate. Nothing
> SpringShield writes ever uses those formats.

## Quality gates

`mvn verify` runs all of these, and CI runs the same command on JDK 21 and 25:

| Gate | Tool | Fails the build when |
|---|---|---|
| Code format | `spring-javaformat` | A source file does not match the Spring code style |
| Toolchain | `maven-enforcer` | JDK is below 21, or Maven below 3.9 |
| Dependency convergence | `maven-enforcer` | A transitive dependency resolves to conflicting versions |
| Static analysis | SpotBugs + Find Security Bugs | Any bug or security pattern is detected |

Formatting violations are fixable in one command:

```bash
mvn spring-javaformat:apply
```

SpotBugs runs at `threshold=Low`, `effort=Max` — it reports low-confidence findings too,
which is deliberate for a security library. Suppressions go in `spotbugs-exclude.xml` and
must carry a comment explaining why the finding does not apply, so each one stays a
reviewable decision.

Dependency and CVE updates are handled by Dependabot rather than a build-time scanner, to
keep `mvn verify` fast.

## Contributing

Standing rules for changes to this project:

- Never reimplement what Spring Security already provides.
- Security changes require negative tests, not just happy-path tests.
- `spring-shield-core` takes no dependency beyond `spring-security-core`.
- Public API changes are breaking changes and follow the deprecation policy.

## License

[Apache License 2.0](LICENSE).
