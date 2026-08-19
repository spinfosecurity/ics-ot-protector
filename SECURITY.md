# Security Policy

## Supported Versions

ICS OT Protector is a **scanning/detection tool portfolio**, not a versioned service. The latest commit on `main` is always the supported version.

| Version | Supported |
|---------|-----------|
| Latest (`main`) | ✅ |
| Older commits | ❌ Use latest |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security flaw in this tool itself (e.g., unsafe file writes, path traversal in output handling, or unsafe subprocess execution), please report it privately:

1. Open a [GitHub private security advisory](https://github.com/spinfosecurity/water-utility-protector/security/advisories/new)
2. **Include:** Description of the issue, reproduction steps, and potential impact
3. **Response time:** We aim to acknowledge reports within 72 hours and resolve confirmed issues within 14 days

## Scope

This project is a **read-only network scanner portfolio** that:
- Opens TCP connections to check port reachability
- Does **not** send exploit payloads or modify remote systems
- Does **not** collect or transmit data externally

Vulnerabilities in the tool's own code (output handling, file writes, argument parsing) are in scope.

## Ethical Use

These tools are intended **exclusively for authorized security assessments** of critical infrastructure OT/SCADA/ICS environments. Unauthorized scanning is illegal and outside the intended use of this software.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution guidelines.
