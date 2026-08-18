# Configuration

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
| `springshield.jwt.issuer-uri` | *(unset)* | Identity provider issuing your bearer tokens. Setting it switches JWT validation on. |
| `springshield.jwt.audiences` | *(empty)* | Values this service answers to. Empty means the audience is **not checked**, so any valid token from the issuer is accepted. |
| `springshield.jwt.claim-mapping.permissions` | `scope` | Token claim mapped to permission authorities. |
| `springshield.jwt.claim-mapping.roles` | *(unset)* | Token claim mapped to `ROLE_` authorities. Unset means roles are not read from tokens. |

These are enforced. SpringShield contributes a `SecurityFilterChain` that permits the listed
patterns and requires authentication for everything else, verified by tests that issue real
requests through the chain.

For authentication, publish a [SecurityUserProvider](username-password.md) or configure
[JWT bearer tokens](jwt.md). The chain also keeps
Spring Boot form login and HTTP Basic as the sign-in mechanisms.

## Configuration mistakes stop startup

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

## Planned

Not yet implemented, listed so the intended shape is clear: OIDC login for browser
applications, and JPA/JDBC adapters for loading users and permissions.


[Back to the README](../README.md)
