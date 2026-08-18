# Contributing

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

## Standing rules

Rules that apply to every change:

- Never reimplement what Spring Security already provides.
- Security changes require negative tests, not just happy-path tests.
- `spring-shield-core` takes no dependency beyond `spring-security-core`.
- Public API changes are breaking changes and follow the deprecation policy.


[Back to the README](../README.md)
