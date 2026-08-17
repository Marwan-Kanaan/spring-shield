# SpringShield

An opinionated, secure-by-default Spring Boot starter that orchestrates Spring Security.

> **Status: pre-alpha, not usable yet.**
> The build skeleton and module layout exist. No security behaviour is implemented, and
> nothing has been published. The configuration shown under
> [Intended developer experience](#intended-developer-experience) is the design target,
> not current behaviour. Do not add this to an application expecting it to secure anything.

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
| `springshield-core` | Public abstractions. No compile dependencies, so it forces no framework or persistence choice. |
| `springshield-autoconfigure` | Spring Boot integration, configuration properties and default wiring. Internal. |
| `springshield-spring-boot-starter` | The dependency you add. Aggregator only, no logic. |

Optional integrations (JPA, JDBC, OAuth2/OIDC SSO) will live in separate modules so
applications that do not use them do not inherit their dependencies.

## Intended developer experience

Design target, **not yet implemented**:

```yaml
springshield:
  authentication:
    mode: jwt
  jwt:
    issuer-uri: https://identity.example.com
    audiences:
      - https://api.example.com
  web:
    public-endpoints:
      - /actuator/health
      - /api/public/**
```

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

## Contributing

Standing rules for changes to this project:

- Never reimplement what Spring Security already provides.
- Security changes require negative tests, not just happy-path tests.
- `springshield-core` stays free of compile dependencies.
- Public API changes are breaking changes and follow the deprecation policy.

## License

[Apache License 2.0](LICENSE).
