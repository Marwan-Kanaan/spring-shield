# Password encoding

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


[Back to the README](../README.md)
