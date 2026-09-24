# Contributing

Bug reports and patches are welcome. For a suspected vulnerability, use the [security policy](SECURITY.md), not a public issue.

## Getting set up

Go 1.26+ is the only prerequisite. `golangci-lint` and `govulncheck` are pinned as `tool` directives in `go.mod`, so there is nothing separate to install.

```bash
git clone https://github.com/kanywst/y509
cd y509
make run    # builds and opens the demo chain
```

## Before you open a pull request

```bash
make lint       # must report 0 issues
make test       # must pass
make vulncheck  # must be clean
```

CI runs the same three. `make test-coverage` gates at 80%; a patch that drops below it will fail.

## What gets merged

- One commit per logical change. A refactor and a behaviour change belong in separate commits.
- Commit messages in English, conventional-commits style. The subject says what changed, the body says why.
- New behaviour needs a test. `pkg/certificate` mints its own certificates rather than checking in fixtures, so a chain with the shape you need is a few lines away; see `serverChain` in `connect_test.go`.

## Things worth knowing about the codebase

- `View()` is pure: it never mutates the model. Resizing and re-rendering go in `Update`, via `resizeComponents()` and `refreshViewportContent()`.
- Key bindings go through `internal/model/keys.go`, which also generates the `?` overlay.
- `pkg/certificate` never writes to stderr by default; a stray line corrupts the TUI. Its logger is a no-op until the app sets one.
- The `--json` contract in `pkg/certificate/report.go` is a separate translation layer, not json tags on internal structs. `TrustLevel` and `ChainProblem` are iota constants and must not leak as numbers. Only strings, timestamps and bools cross it, and slices marshal as `[]`, never `null`.

## Reporting a bug

Attach the certificate if you can. `y509 export` writes one out, and a chain from a public server is public data.

## Adding a STARTTLS protocol

Write a `func(net.Conn) error` prelude in `pkg/certificate/connect.go` and add it to `startTLSNegotiators` and `StartTLSProtocols`. The `--starttls` help and the "unsupported protocol" error update themselves.

Test it against a fake server over `net.Pipe`, including the awkward cases: a multi-line greeting, an untagged response, a refusal.
