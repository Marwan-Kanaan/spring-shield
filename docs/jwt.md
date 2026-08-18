# JWT bearer tokens

Add the resource server starter and set the issuer:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

```yaml
springshield:
  jwt:
    issuer-uri: https://identity.example.com
    audiences:
      - https://api.example.com
```

Setting `issuer-uri` is what switches JWT validation on — there is no separate enable flag,
so you cannot ask for JWT mode without supplying the issuer it needs.

Every token is checked for signature, expiry, issuer, and audience. All of it is Spring
Security's OAuth2 resource server; SpringShield chooses the validators and never parses a
token or reads an unvalidated claim.

## Set `audiences`

It is optional and defaults to empty, which means **the audience is not checked at all**.
Any valid token from that issuer is then accepted — including one the issuer minted for a
different service entirely. If your identity provider serves more than one application, set
this.

Several values mean *any one of them*, not all: a token is accepted when its `aud` claim
contains at least one. That suits a service known by more than one name.

## Turning claims into authorities

A validated token's claims become the authorities `@RequiresPermission` and `@RequiresRole`
check against:

```yaml
springshield:
  jwt:
    claim-mapping:
      permissions: scope   # default
      roles: roles         # unset by default
```

```text
permissions claim   invoice.read  ->  authority  invoice.read
roles claim         ADMIN         ->  authority  ROLE_ADMIN
```

So a token carrying `scope: "invoice.read"` satisfies `@RequiresPermission("invoice.read")`
with no extra configuration. Either claim may be a space-delimited string or a list.

**`roles` is unset by default, deliberately.** There is no standard roles claim, and quietly
adopting whatever an issuer happens to put in a claim called `roles` or `groups` could grant
roles nobody configured. Name the claim to opt in.

Role values must be **bare names** — `ADMIN`, not `ROLE_ADMIN`. The prefix is added during
mapping, so a value that already carries it becomes `ROLE_ROLE_ADMIN` and matches nothing.
If a role that should match does not, check the issuer's claim format first.

Roles from a token are also expanded through your `SecurityPermissionProvider`, if you
publish one, so a token carrying only `ADMIN` can still satisfy a permission that role grants.

> **This runs on every request.** Bearer token authentication is stateless, so the token is
> converted afresh each time and the provider is called each time — unlike the username and
> password path, where it happens once at sign-in. A provider that queries a database adds a
> query to every authenticated request. Keep it cheap, cache inside it, or leave `roles`
> unconfigured and let the token carry permissions directly.

Nested claim paths such as Keycloak's `realm_access.roles` are not supported. Declare your
own `JwtAuthenticationConverter` bean for those.

## Startup depends on your identity provider

The issuer's metadata is fetched **during startup**, from
`<issuer-uri>/.well-known/openid-configuration`. If the identity provider is unreachable
then, the application does not start.

That is deliberate — fail-fast rather than fail-open, and a mistyped issuer URI is caught at
deployment instead of surfacing later as rejected requests. The cost is a startup dependency
on the provider. If you must start during a provider outage, declare your own `JwtDecoder`
built with `NimbusJwtDecoder.withJwkSetUri(...)` or from a key you already hold, and
SpringShield backs off.

Signing keys are refreshed from the JWKS endpoint after startup, so routine key rotation
needs no configuration change and no restart.

[Back to the README](../README.md)
