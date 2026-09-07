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

**One commit, one logical change.** A refactor and a behaviour change in the same commit are two commits. This matters more than commit count — a large single-purpose commit is fine.

**Commit messages in English, conventional-commits style.** `feat(scope): ...`, `fix: ...`, `docs: ...`, `chore: ...`. The subject says what changed; the body says *why*, in prose. "Fixed bug" tells a future reader nothing.

**Explain the non-obvious in comments, not the obvious.** The code says what it does. A comment earns its place by saying why it is that way — which constraint, which spec, which bug. Several already in the tree exist because the naive version was wrong, and they say so.

**New behaviour needs a test.** Certificate handling especially: the package mints its own certificates in tests rather than checking in fixtures, so a chain with the exact shape you need is a few lines away. Look at `serverChain` in `pkg/certificate/connect_test.go`.

## Things worth knowing about the codebase

The [CLAUDE.md](CLAUDE.md) file at the root is written for AI assistants but is the most current architecture document, and is worth reading whichever kind of contributor you are. The invariants it lists are real ones — breaking them is how the panes end up different heights or the TUI corrupts itself with a stray log line.

Three that catch people out:

- **`View()` must be pure.** It returns a `tea.View` and never mutates the model. Anything that resizes or re-renders belongs in `Update`, via `resizeComponents()` or `refreshViewportContent()`.
- **Every key binding goes through `internal/model/keys.go`.** `keyMap` implements `help.KeyMap`, so the `?` overlay is generated from the same source. A binding added anywhere else will not appear in the help.
- **`pkg/certificate` never writes to stderr by default.** It keeps its own logger, defaulting to a no-op, because a stray line of output corrupts the TUI. Route diagnostics through that logger.

The `--json` contract in `pkg/certificate/report.go` is a deliberate translation layer rather than json tags on the internal structs. `TrustLevel` and `ChainProblem` are iota constants; marshalling them directly would publish their numeric values as an API and break every consumer the moment a constant is inserted. Everything crossing that boundary is a string, a timestamp, or a bool. If you add a field, add it there too, and keep slices initialised so they marshal as `[]` rather than `null`.

## Reporting a bug

The certificate that triggers it is worth more than a description of it. `y509 export` will write one out, and a chain that reproduces the problem is usually safe to attach — it is public data that a server hands to anyone who connects. If it is from an internal PKI and you would rather not, say what shape it is: how many certificates, which one is missing, what the issuers look like.

Include `y509 version`, your OS and terminal, and the exact command line.

## Adding a STARTTLS protocol

The most likely first contribution, so it is worth spelling out. Every prelude lives in `pkg/certificate/connect.go` and is one function of the shape `func(net.Conn) error`. Add it to the `startTLSNegotiators` table and to `StartTLSProtocols`; the `--starttls` help text and the "unsupported protocol" error both read from that slice, so they update themselves.

Test it against a fake server over `net.Pipe`, the way the existing five are tested, and cover the awkward case as well as the happy one — a multi-line greeting, an untagged response, a server that refuses. That awkward case is usually the entire reason the prelude is not a one-liner.
