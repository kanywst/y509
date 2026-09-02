# Security Policy

y509 reads X.509 certificates from files, from stdin, and from whatever a remote server chooses to send during a TLS handshake. All of that is untrusted input, and `y509 validate` is built to gate CI on its exit code.

## Supported versions

| Version | Supported |
| :--- | :--- |
| Latest release | Yes |
| Anything older | No — upgrade first |

Fixes ship as a new release. There are no backport branches.

## Reporting a vulnerability

Report privately through GitHub: **[open a draft advisory](https://github.com/kanywst/y509/security/advisories/new)**. That is the only channel; please do not open a public issue for a suspected vulnerability.

Please include what you have of:

- The version (`y509 version`) and the OS
- The certificate, chain, or host that triggers it — a minimal PEM is ideal
- The exact command line
- What you expected versus what happened

What to expect:

- Acknowledgement within 7 days
- An assessment of whether it is in scope within 14 days
- A fix in a patch release, published together with a GitHub Security Advisory crediting you unless you would rather stay anonymous

## Scope

In scope:

- A panic, hang, or unbounded allocation reached by parsing a malformed certificate or chain, including one sent by a remote server during `y509 <host>:<port>`
- `y509 validate` exiting `0` for a chain a TLS client would reject, or exiting non-zero for one it would accept. The exit code is a contract that CI depends on
- The TLS client doing anything beyond the handshake documented in the README
- Writing outside the path the user asked for, via `export`, `--log-file`, or the default log destination
- Leaking key material or certificate contents to a location more permissive than intended

Out of scope, because it is the documented design:

- The TUI handshake deliberately verifies nothing. `y509 example.com:443` is an inspection tool, and refusing to show you a broken chain would defeat the purpose. `validate` is the entry point that verifies
- Reporting a chain as `self-anchored`, `broken`, or misconfigured. That is the tool working
- Vulnerabilities in Go's standard library or in third-party dependencies. Report those to their maintainers. If y509 needs a version bump to pick up a fix, a normal issue or pull request is the right place

## Downstream packagers

y509 is packaged outside this repository, including the FreeBSD [`security/y509`](https://www.freshports.org/security/y509/) port and the [`kanywst/tap`](https://github.com/kanywst/homebrew-tap) Homebrew cask. Advisories are published here first; packaging bugs specific to a distribution belong with that packager.
