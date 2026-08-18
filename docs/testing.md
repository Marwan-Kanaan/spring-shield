# Testing your application

Add the test module at test scope:

```xml
<dependency>
    <groupId>io.github.marwan-kanaan</groupId>
    <artifactId>spring-shield-test</artifactId>
    <version>0.1.0-SNAPSHOT</version>
    <scope>test</scope>
</dependency>
```

## Running a test as a caller

`@WithSecurityUser` runs a test as someone holding the roles and permissions you name:

```java
@Test
@WithSecurityUser(permissions = "invoice.read")
void shouldReturnInvoices() {
    assertThat(this.invoices.findAll()).isNotEmpty();
}

@Test
@WithSecurityUser(roles = "ADMIN")
void shouldAllowAnAdministratorToDelete() {
    this.invoices.deleteAll();
}
```

Spring Security's `@WithMockUser` can do the same, but only if you already know how
SpringShield maps its model onto authorities — permissions verbatim, roles with a `ROLE_`
prefix. Getting that wrong gives you a test failing for a reason unrelated to the code under
test. This applies the mapping for you.

It needs a Spring test context, exactly like `@WithMockUser`: `@SpringBootTest`, a slice such
as `@WebMvcTest`, or `@ExtendWith(SpringExtension.class)`. On a plain JUnit test it is
silently ignored and the authentication stays null.

## Bad values fail the test, not the assertion

Roles and permissions go through the same validation as production code, so this fails
immediately with an explanation:

```java
@WithSecurityUser(roles = "ROLE_ADMIN")   // rejected: the prefix is added for you
```

Without that, the value would become `ROLE_ROLE_ADMIN`, match nothing, and leave you
debugging an access denied that had nothing to do with your code.

## What it does not do

**It never weakens what you are testing.** It populates a security context the way an
authenticated request would. It does not disable a check, skip the filter chain, or grant an
authority your application would not have granted — a helper that made authorization pass
would leave you with tests that stay green while the application stops being safe.

**It does not authenticate.** There is no password and no token involved, so it tests what a
caller may do once authenticated, not whether they can authenticate at all. Cover the sign-in
path with a real request:

```java
mvc.perform(get("/api/invoices").with(httpBasic("ada", "secret")))
    .andExpect(status().isOk());
```

## Testing denial

Prove the negative too. A component that rejects everything passes every negative test, so
assert both directions:

```java
@Test
@WithSecurityUser(permissions = "invoice.list")
void shouldDenyACallerWithoutTheRequiredPermission() {
    assertThatExceptionOfType(AccessDeniedException.class)
        .isThrownBy(() -> this.invoices.findAll());
}
```

[Back to the README](../README.md)
