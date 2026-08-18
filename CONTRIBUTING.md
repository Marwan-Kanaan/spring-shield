# Contributing

Thanks for considering a contribution. This is a security library, so the bar for a change is
a little higher than usual, and this page says where that bar sits so nothing comes as a
surprise in review.

## Building

Requires **JDK 21**. Maven uses the JDK from `JAVA_HOME`, which may differ from whichever
`java` is first on your `PATH` — if the two disagree, the build enforcer will tell you.

```bash
mvn clean verify
```

That runs every gate. If it passes locally it should pass in CI, which runs the same command
on JDK 21 and 25.

## Quality gates

`mvn verify` fails on any of these:

| Gate | Tool | Fails when |
|---|---|---|
| Code format | `spring-javaformat` | A source file does not match the Spring code style |
| Toolchain | `maven-enforcer` | JDK is below 21, or Maven below 3.9 |
| Dependency convergence | `maven-enforcer` | A transitive dependency resolves to conflicting versions |
| Static analysis | SpotBugs + Find Security Bugs | Any bug or security pattern is detected |

Formatting is fixable in one command:

```bash
mvn spring-javaformat:apply
```

SpotBugs runs at `threshold=Low`, `effort=Max` — it reports low-confidence findings too,
which is deliberate here. If a finding does not apply, prefer fixing the code so it stops
firing. A suppression goes in `spotbugs-exclude.xml` with a comment explaining why the
finding is wrong, narrowed to one class and one bug pattern. "It was noisy" is not a reason,
and suppressing a Find Security Bugs pattern is a security decision that gets reviewed as
one.

The file is currently empty. Keeping it that way is a goal, not an accident.

## Rules that apply to every change

- **Never reimplement what Spring Security already provides.** SpringShield chooses and wires
  Spring Security's components; it does not verify signatures, hash passwords, or make
  authorization decisions itself. If a change starts adding security logic, that is usually a
  sign the framework already has the mechanism.
- **Security changes need negative tests**, not only happy-path ones. A component that
  rejects everything passes every negative test, so prove both that the right thing is
  allowed and that the wrong thing is denied.
- **Prove behaviour, not wiring.** Asserting that a bean exists says nothing about whether an
  unauthenticated request is actually rejected. Where a real request can be issued through
  the filter chain, issue one.
- **`spring-shield-core` takes no dependency beyond `spring-security-core`.** Every
  dependency added there becomes a dependency of every user.
- **Public API changes are breaking changes.** Renaming or removing a type in
  `spring-shield-core`, or a `springshield.*` property, follows the deprecation policy rather
  than being edited in place.
- **Do not document behaviour you have not verified.** If the Javadoc says the framework does
  something, check that it does. This has been wrong more than once.

## Defaults

A default that is unsafe is a bug, even if it is convenient. Two consequences worth knowing
before proposing one:

- **Fail closed.** When something cannot be resolved, deny rather than allow. An empty result
  that means "grant nothing" must not be reachable by accident from a lookup failure.
- **Do not guess.** Where there is no standard — a roles claim name, for instance — require
  configuration rather than adopting whatever an issuer happens to provide. Guessing can
  grant access nobody configured.

## Tests

- Name tests for the behaviour and the security intent. `shouldRejectRequestWhenPermissionIsMissing`,
  not `shouldCallFilterMethod2`.
- Keep them deterministic: no sleeps, no reliance on the network. Where a test needs an
  identity provider, there is a loopback stub that serves discovery and a key set.
- Use `ApplicationContextRunner` for auto-configuration paths, including the back-off and
  disabled cases.

## Commits

A commit message should explain the problem and the decision, not restate the diff. Where a
change is security-relevant, say what it protects against and what evidence proves it. Where
it deviates from an obvious approach, say why the obvious approach was wrong.

Keep changes small and independently reviewable. Unrelated cleanup belongs in its own commit.

## Reporting a vulnerability

Not through an issue or a pull request — see [SECURITY.md](SECURITY.md).
