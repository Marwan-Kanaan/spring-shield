# Username and password

Publish a `SecurityUserProvider` and SpringShield uses it to authenticate:

```java
@Component
class JdbcSecurityUserProvider implements SecurityUserProvider {

    @Override
    public Optional<SecurityUser> findByUsername(String username) {
        return this.accounts.findByUsername(username)
            .map(account -> SecurityUser.builder(account.username())
                .encodedPassword(account.passwordHash())
                .role(SecurityRole.of(account.role()))
                .enabled(account.isActive())
                .accountNonLocked(!account.isLocked())
                .build());
    }
}
```

That is the whole integration. SpringShield adapts it to the `UserDetailsService` Spring
Security authenticates through, so you return your own domain types and never touch Spring
Security's.

**`encodedPassword` must already be hashed.** SpringShield never encodes it for you and never
compares it itself — Spring Security does both. Encode with the injected `PasswordEncoder`
when you create the account. A user with no encoded password cannot sign in with a password
at all, which is what you want for accounts that exist only for token access.

Return `Optional.empty()` for an unknown user; never throw. SpringShield reports the same
failure for an unknown user as for a wrong password, so neither reveals which accounts exist.

## Expanding roles into permissions

Most applications store coarse roles against a user and define separately what each role
allows. Publish a `SecurityPermissionProvider` for the second half:

```java
@Component
class JdbcSecurityPermissionProvider implements SecurityPermissionProvider {

    @Override
    public Set<SecurityPermission> findPermissions(Set<SecurityRole> roles) {
        return this.rolePermissions.findByRoles(roles);
    }
}
```

It receives **all** the user's roles in one call, so a user with five roles still costs one
query rather than five on a path that runs at every sign-in.

Without one, SpringShield grants no extra permissions — authorization falls back to whatever
is already on the `SecurityUser`. A default that guessed would hand out access nobody
configured.

If resolution fails, **throw**. Returning an empty set would be indistinguishable from "these
roles grant nothing", so a database outage would quietly sign users in with fewer rights than
they hold.

[Back to the README](../README.md)
