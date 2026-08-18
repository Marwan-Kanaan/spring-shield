# Method authorization

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


[Back to the README](../README.md)
