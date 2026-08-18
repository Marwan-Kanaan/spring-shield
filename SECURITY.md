# Security policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.** A public report tells everyone
running the affected code about the weakness at the same moment it tells us, including people
who would use it.

Report it privately through GitHub instead: open the repository's **Security** tab and choose
**Report a vulnerability**. That creates a private advisory only the maintainers can see.

If private reporting is unavailable to you for any reason, contact the maintainer through the
account listed on the repository rather than filing an issue.

### What helps

The more of this you can include, the faster it can be confirmed:

- What an attacker can achieve, not only what looks wrong.
- The affected version or commit.
- Configuration needed to reproduce it, especially any `springshield.*` properties.
- A minimal reproduction, if you have one.

Please do not include real credentials, tokens, or production data in a report.

### What to expect

This is a small project with no dedicated security team, so a realistic commitment rather
than a reassuring one:

- An acknowledgement that the report was received and read.
- An assessment of whether it is a genuine vulnerability, and its severity.
- A fix, and a released version containing it, for anything confirmed.
- Credit in the advisory, unless you would rather not be named.

If a report turns out not to be a vulnerability, you will get an explanation of why rather
than silence.

## Supported versions

Nothing has been published yet. SpringShield is pre-alpha and its public API may still change
without notice, so there is no released version to patch and no support window to state.

Once there is a release, this section will list which versions receive security fixes. Until
then, treat the `main` branch as the only supported code, and do not run it anywhere that
matters.

## Scope

The [threat model](docs/threat-model.md) states what SpringShield defends against and what it
deliberately leaves to the application. A report that something in the "not covered" list is
not covered is not a vulnerability, though an argument that it should be covered is a welcome
issue.

SpringShield is an orchestration layer over Spring Security. A weakness in Spring Security,
Spring Boot, or another dependency belongs to that project, and reporting it there gets it
fixed for everyone rather than only here. Their reporting channels:

- Spring Security and Spring Boot: https://spring.io/security-policy

What is in scope here is SpringShield's own behaviour, for example:

- A default that is less safe than documented.
- Configuration that appears to restrict access but does not.
- An error response revealing more than it should.
- Auto-configuration that fails to back off, or fails open rather than closed.
- A documented security control that does not actually hold.

Reports that a default is inconvenient, rather than unsafe, are welcome as ordinary issues.
