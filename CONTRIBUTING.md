# Contributing

Bug reports and patches are both welcome. This file is the short version of what the maintainer will look for, so you can find out before you write the code rather than after.

For a suspected vulnerability, use the [security policy](SECURITY.md) instead. Do not open a public issue.

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

Four invariants that are easy to break by accident:

- `View()` is pure. It returns a `tea.View` and never mutates the model. Resizing and re-rendering belong in `Update`, via `resizeComponents()` and `refreshViewportContent()`.
- Key bindings go through `internal/model/keys.go`, which also generates the `?` overlay. A binding added anywhere else will not appear in the help.
- `pkg/certificate` never writes to stderr by default. It keeps its own logger, defaulting to a no-op, because a stray line corrupts the TUI.
- The `--json` contract in `pkg/certificate/report.go` is a translation layer, not json tags on the internal structs. `TrustLevel` and `ChainProblem` are iota constants, so marshalling them directly would publish their numbers as an API. Everything crossing that boundary is a string, a timestamp, or a bool, and slices are initialised so they marshal as `[]` rather than `null`.

## Reporting a bug

The issue template asks for the fields. The one worth going out of your way for is the certificate itself: `y509 export` will write one out, and a chain a public server presents is public data, so it is normally safe to attach.

## Adding a STARTTLS protocol

Every prelude lives in `pkg/certificate/connect.go` and is one function of the shape `func(net.Conn) error`. Add it to the `startTLSNegotiators` table and to `StartTLSProtocols`; the `--starttls` help text and the "unsupported protocol" error both read from that slice, so they update themselves.

Test it against a fake server over `net.Pipe`, like the existing ones, and cover the awkward case as well as the happy one: a multi-line greeting, an untagged response, a server that refuses. That case is usually the whole reason the prelude is not a one-liner.
