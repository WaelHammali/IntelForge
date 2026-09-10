# Security Policy

## Scope

IntelForge is an **offensive-security tool**. It is intended only for use against
systems you own or have explicit written authorisation to test. Misuse is the
responsibility of the operator, not the project.

## Reporting a vulnerability

If you find a security issue in IntelForge itself (for example: command
injection through a target string, unsafe deserialization of a saved state file,
or a way for a scanned host to execute code on the operator's machine), please
**do not open a public issue**.

Instead, use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on this repository.

Please include:

- affected version / commit
- a minimal reproduction
- the impact you observed

You can expect an initial response within a few days.

## Supported versions

Only the latest `main` is supported. Fixes are not back-ported to tags.
