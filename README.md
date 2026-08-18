# SpringShield

An opinionated, secure-by-default Spring Boot starter that orchestrates Spring Security.

> **Status: pre-alpha, nothing published yet.**
> Working: deny-by-default request authorization, username and password authentication via
> your own user store, JWT bearer token validation, permission and role annotations, password
> encoding, a consistent error contract, and test helpers. Not yet built: OIDC login and
> persistence adapters. The public API may still change without notice.

## What it is

SpringShield removes repetitive security configuration from Spring Boot applications without
replacing Spring Security.

It is a thin orchestration and developer-experience layer. Authentication, authorization,
password encoding, JWT validation and the filter chain remain Spring Security's job.
SpringShield's contribution is sensible defaults and a small set of extension points,
arranged so the secure path is also the easy one.

## What it is not

It is **not** a replacement for Spring Security, and not a second security engine beside it.
It does not implement its own cryptography, JWT verification, password hashing or
authentication protocols. Where Spring Security already solves a problem, SpringShield
delegates to it.

If SpringShield's defaults do not suit your application, you keep normal Spring Security:
declare your own beans and SpringShield gets out of the way.

## Quick start

Add the starter:

```xml
<dependency>
    <groupId>io.github.marwan-kanaan</groupId>
    <artifactId>spring-shield-spring-boot-starter</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

Name the endpoints that should be reachable without signing in. Everything else requires
authentication:

```yaml
springshield:
  web:
    public-endpoints:
      - /actuator/health
      - /api/public/**
```

Then choose how callers authenticate — [your own user store](docs/username-password.md) or
[JWT bearer tokens](docs/jwt.md) — and guard what they may do:

```java
@RequiresPermission("invoice.read")
public List<Invoice> findInvoices() { ... }
```

## Documentation

| Guide | Covers |
|---|---|
| [Configuration](docs/configuration.md) | Every `springshield.*` property, and why bad values stop startup |
| [Username and password](docs/username-password.md) | Authenticating against your own user store |
| [JWT bearer tokens](docs/jwt.md) | Issuer and audience validation, claim mapping, key rotation |
| [Method authorization](docs/authorization.md) | `@RequiresPermission`, `@RequiresRole`, and proxy limitations |
| [Error responses](docs/errors.md) | The 401 and 403 contract, and what it never reveals |
| [Password encoding](docs/password-encoding.md) | The default encoder and how to replace it |
| [Testing](docs/testing.md) | Test helpers for applications using SpringShield |
| [Threat model](docs/threat-model.md) | What SpringShield defends against, and what it does not |
| [Contributing](CONTRIBUTING.md) | Quality gates and the rules every change follows |
| [Security policy](SECURITY.md) | Reporting a vulnerability, and what is in scope |

## Baseline

| | Version |
|---|---|
| Java | 21 |
| Spring Boot | 4.1.0 |
| Spring Security | 7.1.0 (managed by Spring Boot) |
| Build | Maven 3.9+ |

Spring Security's version is inherited from Spring Boot's dependency management rather than
pinned independently, so the stack stays internally consistent and picks up Boot's security
patches.

## Modules

| Module | Role |
|---|---|
| `spring-shield-core` | Public abstractions and annotations. Depends only on `spring-security-core`, so it forces no Spring Boot, web or persistence choice. |
| `spring-shield-autoconfigure` | Spring Boot integration, configuration properties and default wiring. Internal. |
| `spring-shield-test` | Test helpers for applications. Add at test scope. |
| `spring-shield-spring-boot-starter` | The dependency you add. Aggregator only, no logic. |

Optional integrations (JPA, JDBC, OAuth2/OIDC SSO) will live in separate modules so
applications that do not use them do not inherit their dependencies.

## Backing off

The most important behaviour of a starter is what happens when the application wants control.
Every default SpringShield contributes is guarded by `@ConditionalOnMissingBean`, so an
explicit application bean always wins:

```java
@Bean
SecurityFilterChain applicationSecurity(HttpSecurity http) {
    // SpringShield does not contribute a competing chain.
}
```

This composes with Spring Boot rather than fighting it. Boot's own default chain is guarded
by `@ConditionalOnDefaultWebSecurity`, which in Spring Boot 4.1 requires that no
`SecurityFilterChain` bean is present — so when SpringShield contributes one, Boot's default
withdraws on its own.

Setting `springshield.enabled=false` disables SpringShield entirely. Note that this does not
disable security: Spring Boot's own chain takes over, so the application stays protected
rather than becoming open.

## Building

Requires JDK 21. Maven uses the JDK from `JAVA_HOME`, which may differ from whichever `java`
is first on your `PATH`.

```bash
mvn clean verify
```

## License

[Apache License 2.0](LICENSE).
