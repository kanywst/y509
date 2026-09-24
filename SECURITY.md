# Security Policy

Everything y509 reads (files, stdin, a server's handshake) is untrusted input, and CI gates on the exit code of `y509 validate`.

## Supported versions

| Version | Supported |
| :--- | :--- |
| Latest release | Yes |
| Anything older | No — upgrade first |

Fixes ship as a new release. There are no backport branches.

## Reporting a vulnerability

**[Open a draft advisory](https://github.com/kanywst/y509/security/advisories/new)** on GitHub. That is the only channel; do not open a public issue.

Include what you can of:

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

- The TUI handshake verifying nothing. It is an inspection tool; `validate` is what verifies
- Reporting a chain as `self-anchored`, `broken`, or misconfigured. That is the tool working
- Bugs in Go or in dependencies. Report those upstream; if y509 needs a version bump, a normal issue or PR is fine

## Downstream packagers

Advisories are published here first. Packaging bugs belong with the packager: the FreeBSD [`security/y509`](https://www.freshports.org/security/y509/) port, the [`kanywst/tap`](https://github.com/kanywst/homebrew-tap) Homebrew cask, and others.
