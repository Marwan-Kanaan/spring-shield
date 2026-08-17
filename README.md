# SpringShield

An opinionated, secure-by-default Spring Boot starter that orchestrates Spring Security.

> **Status: pre-alpha, not usable yet.**
> The public API, configuration properties and build exist and are tested. What does **not**
> exist yet is any enforcement: there is no security filter chain, no authentication and no
> authorization. Configuration binds and validates, but changes nothing at runtime, and
> nothing has been published. Do not add this to an application expecting it to secure
> anything.

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
| `spring-shield-core` | Public abstractions. No compile dependencies, so it forces no framework or persistence choice. |
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

> **These properties bind and validate today, but nothing enforces them yet.**
> `public-endpoints` does **not** currently affect request handling — the filter chain that
> reads it is not implemented. Do not rely on it to protect anything.

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
- `spring-shield-core` stays free of compile dependencies.
- Public API changes are breaking changes and follow the deprecation policy.

## License

[Apache License 2.0](LICENSE).
