# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private vulnerability
reporting on this repository (Security → Advisories → "Report a vulnerability"), which notifies the
maintainers without disclosing details publicly.

Include, as far as you can:

- the version or commit you tested,
- the configuration required to reproduce it (redact credentials and keys),
- the impact you believe it has, and
- any proof-of-concept steps.

You will get an acknowledgement, an assessment, and a coordinated disclosure timeline.

## Supported versions

Security fixes land on the current release line. Preview releases are supported until the next
preview supersedes them, so run a current build if you are exposing the server to untrusted traffic.

## Scope

Useful reports include configuration that bypasses validation and produces unsafe behaviour, request
handling flaws (path traversal, header injection, request smuggling), TLS or certificate-handling
mistakes, and sandbox escapes in the module runtime.

The following are not vulnerabilities in this project by themselves: behaviour inherited from the
Caddy configuration model that is documented as intentional, and configurations that this build
refuses with a located error (refusing a configuration is the intended failure mode).
