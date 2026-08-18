# Threat model

What SpringShield defends against, what it deliberately does not, and where the line between
the two sits.

The second half matters more than the first. A security library that leaves you believing it
handles something it does not is worse than one that handles nothing, so every gap below is
stated plainly rather than left to be discovered.

## The shape of it

SpringShield sits between a caller and your application, and its job is narrow:

```text
caller ──► filter chain ──► method authorization ──► your code
           │                │
           │                └── @RequiresPermission / @RequiresRole
           └── authentication, deny-by-default request rules
```

It decides **who a caller is** and **whether they may invoke something**. It does not know
what your data is, so anything that depends on the object being acted upon is yours.

## Covered

| Threat | What stops it | Evidence |
|---|---|---|
| **Forged tokens** | Spring Security verifies the signature against keys published by the issuer, before any claim is read. | A token signed with an unpublished key, an unsigned `alg: none` token, one with its signature stripped, and one whose payload was edited after signing are all rejected. |
| **Accidental public endpoints** | Deny by default. Only paths listed in `public-endpoints` are open, patterns are validated at startup, and `/**` is rejected outright. | Unknown paths return 401; `/**` fails startup with an explanation. |
| **Authorization bypass via competing chains** | SpringShield contributes one filter chain and is ordered before Boot's, so exactly one exists. Two chains would make the effective policy depend on which matched first. | A test asserts exactly one `SecurityFilterChain` bean. |
| **Privilege escalation through claims** | Only claims that survived signature, issuer, audience and expiry validation become authorities. Roles are read only from a claim you name. | A token for a different issuer or audience is rejected; a `roles` claim is ignored unless configured. |
| **Confused deputy across services** | Audience validation. A token the same issuer minted for another service is rejected. | Covered by test, and by an integration test over the full chain. |
| **CSRF** | Left at Spring Security's default. SpringShield never disables it. | A state-changing request without a token is rejected; with one it succeeds. |
| **Sensitive data leakage in errors** | Error responses carry a fixed message and a stable code. Never the exception message, a stack trace, the missing authority, or the query string. | Asserted against the response body. |
| **Insecure defaults** | Nothing is public until named, no password means no password sign-in, no roles claim is adopted by guess, and the permission provider grants nothing by default. | Each has a test. |
| **Password disclosure from storage** | `DelegatingPasswordEncoder` with bcrypt. Salted, and the algorithm is recorded so it can be migrated. | Encoding is verified to be salted and never to contain the plaintext. |

## Not covered

These are real threats that SpringShield does **not** address. Most need state, storage, or
knowledge of your domain, which a stateless authorization layer does not have.

| Threat | Why not | What to do |
|---|---|---|
| **Brute force and credential stuffing** | Needs rate limiting and attempt tracking, which needs shared state and a policy decision about lockout versus throttling. There is no lockout, no throttling, and no attempt counting. bcrypt slows an *offline* attack on a stolen database; it does nothing against online guessing. | Rate limit at the gateway or with a filter. Consider account lockout carefully — done naively it becomes a denial-of-service against your own users. |
| **Insecure direct object references** | SpringShield authorizes *the call*, not *the object*. `@RequiresPermission("invoice.read")` says the caller may read invoices, not that they may read **this** invoice. | Check ownership in your service layer, after resolving the object. This is the most commonly missed gap in applications using any authorization library. |
| **Replay** | Nothing tracks `jti` or nonces. A stolen token remains usable until it expires. | Keep token lifetimes short at the issuer. For high-value operations, add idempotency keys or a nonce of your own. |
| **Token theft in transit** | SpringShield never sees the transport. | Terminate TLS properly and do not accept bearer tokens over plaintext HTTP. |
| **CORS misconfiguration** | SpringShield configures no CORS policy at all, permissive or otherwise. | Configure it explicitly with Spring Security if a browser on another origin calls your API. |
| **Session fixation** | Spring Security's default session handling applies unchanged; SpringShield neither strengthens nor weakens it. | Verify it if you use sessions. Bearer token deployments are typically stateless and unaffected. |
| **Multi-tenant isolation** | There is no tenant concept. A permission is a permission regardless of which tenant's data is behind it. | Include tenant context in your own authorization decisions and data access. |
| **Dependency vulnerabilities** | Dependabot raises pull requests for new versions, but there is no build-time scanner, so `mvn verify` will not fail on a known CVE. | Enable Dependabot alerts on the repository, and add SCA to your own pipeline if you need a hard gate. |
| **Denial of service through request size or parsing** | Not addressed at this layer. | Configure request limits at the container or gateway. |

## Residual risks worth naming

Three things are safe by default but become unsafe if configured carelessly:

**An unset audience means no audience check.** `springshield.jwt.audiences` is empty by
default, and an empty list disables the check rather than failing closed. Any valid token from
your issuer is then accepted, including one minted for an entirely different service. If your
identity provider serves more than one application, this is the setting that matters most.

**`springshield.authorization.enabled=false` does not relax one rule.** It stops
`@RequiresPermission` and `@RequiresRole` being enforced at all, so methods that still read as
guarded run unguarded. The annotations stay in the source, which makes the change easy to miss
in review.

**A delegating password encoder still verifies legacy formats.** A stored `{noop}password`
authenticates, because that is how Spring Security supports migrating old data. Treat any such
value in a real user store as something to migrate, not something the encoder protects you
from.

## Trust boundaries

```text
untrusted ─────────────────────────────► trusted
  request path, headers, request body
  bearer token contents, before validation
  claim values, after validation but before mapping

partially trusted
  the identity provider, for what it asserts about identity —
  subject to signature, issuer, audience and expiry checks

trusted
  your SecurityUserProvider and SecurityPermissionProvider
  your application configuration
```

SpringShield trusts your providers completely: whatever authorities they return are granted.
That is the right default — they are your code — but it means a provider that reads roles from
somewhere an attacker influences hands that attacker those roles.

The identity provider is trusted only for what it signs, and only after the signature, issuer,
audience and expiry have been checked. Claim values are still just strings after that: they
become authorities through explicit mapping, never by being present.

## Keeping this honest

This document is only useful if it stays true. When a feature changes what SpringShield
defends against, the change belongs here in the same commit — and a threat moving from **Not
covered** to **Covered** needs a test named in the evidence column, not an assertion that it
now works.

[Back to the README](../README.md)
