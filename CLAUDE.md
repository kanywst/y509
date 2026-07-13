# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Requires Go 1.26+ (see `go.mod`). `golangci-lint` and `govulncheck` are pinned as `tool` directives in `go.mod`, so `make lint` / `make vulncheck` invoke them via `go tool` — no separate install.

```bash
make build       # Build ./y509 with version info via -ldflags
make build-dev   # Faster build without version info, used by `make run`
make run         # Build and launch against testdata/demo/certs.pem
make test        # go test -v ./...
make test-coverage
make lint        # go tool golangci-lint run ./...
make vulncheck   # go tool govulncheck ./...
make tidy        # go mod tidy
make build-all   # Cross-compile for linux/darwin/windows
```

Single test:

```bash
go test ./internal/model -run TestNavigationKeys -v
go test ./pkg/certificate -run TestExportCertificate/PEM_format -v
```

Regenerate the demo asset (requires `vhs`):

```bash
vhs demo.tape   # writes demo.gif; the Hide block also rebuilds the binary
                # and regenerates testdata/demo/certs.pem via gen_demo_certs.go
```

CI (`.github/workflows/test.yml`) runs `make lint`, `make vulncheck`, and `make test-json` on every push/PR to `main`. Releases are cut by tagging `v*`, which triggers `release.yml` → GoReleaser → Homebrew tap update.

## Architecture

The TUI is built on the Charm v2 stack (`charm.land/bubbletea/v2`, `charm.land/lipgloss/v2`, `charm.land/bubbles/v2`, `charm.land/huh/v2`). Anything imported from `github.com/charmbracelet/...` is stale — use the vanity domain.

### Entry flow

`cmd/y509/main.go` → `internal/cmd.Execute` (cobra). The root command (`internal/cmd/root.go`) loads certificates via `pkg/certificate.LoadCertificates`, builds a `model.Model`, and runs `tea.NewProgram(model)`. `AltScreen` and `MouseMode` are declared on the `tea.View` returned from `Model.View()` — there is no `tea.WithAltScreen` / `tea.WithMouseCellMotion` to add.

Subcommands `validate`, `export`, `version`, `completion` are non-TUI and live alongside `root.go` in `internal/cmd/`.

### TUI model (`internal/model/`)

Standard Bubble Tea Model/Update/View. Keep these invariants:

- **`View()` must be pure.** It returns `tea.View`, never mutates the model. Viewport size/content updates live in `Update` via `resizeComponents()` (called from `tea.WindowSizeMsg`) and `refreshViewportContent()` (called whenever the selected cert, active tab, or viewport width changes — i.e. window resize, cursor move, tab switch, filter/search/reset).
- **All keys go through `keys.go`.** `keyMap` implements `help.KeyMap`, so the `?` overlay (`help.Model`) is generated from the same source. When adding a binding, also add it to `ShortHelp()` and the appropriate column of `FullHelp()`.
- **List + viewport are sized in one place.** `resizeComponents` derives both pane geometries from the constants in `constants.go` (`HeaderHeight`, `PaneBorderHeight`, `PaneBorderWidth`, `ListHeaderHeight`, `PaneSideBorderWidth`, `statusBarHeight`). The left pane uses `BorderRight(false)`, so its inner width is `paneWidth - PaneSideBorderWidth` (1), while the right pane has both borders, so width math there uses `PaneBorderWidth` (2). The right pane reserves a one-row scroll indicator (`renderScrollFooter`); `resizeComponents` subtracts `scrollFooterHeight` from the viewport height so both panes stay the same height — change one and you must change the other.
- **The tab strip is width-aware.** `renderTabs` collapses the full `Subject/Issuer/.../Misc` strip to a compact `‹ Active ›  i/n` indicator when it would be wider than the pane. Both forms are exactly two rows tall (label + underline) so the collapse never changes pane height. Don't let it wrap.
- **Cursor lives in `m.list`, not on `Model`.** Read with `m.list.Index()`, write with `m.list.Select(i)` / `CursorUp` / `CursorDown`. Filter/search/reset paths must call `m.list.SetItems(toListItems(...))` (in `list_item.go`) and then `refreshViewportContent`.
- **Right-pane content is rendered by `renderTabContent(width)`** — height-agnostic, the viewport handles vertical truncation. The chain visualization on the Misc tab uses `lipgloss/v2/table` (`renderChainPosition`).
- **Export popup is a `huh.Form`** built fresh in `newExportForm` (`export_form.go`). The filename input has a non-empty validator; `handleExportCommand` additionally closes the popup defensively if it ever sees an empty filename. Append the format extension with `filepath.Ext(filename) == ""`, not `strings.Contains(filename, ".")`.
- **Clipboard copy (`y`) goes through the terminal, not a syscall.** `command.go` emits `tea.SetClipboard(pem)` (OSC52) and shows an alert popup — there is no OS clipboard dependency to mock or feature-gate.

### Certificate package (`pkg/certificate/`)

Loads PEM/DER from a file or stdin, sorts an unordered chain (`SortChain` matches issuers to subjects), validates link integrity (`ValidateChainLinks` decorates each `Info` with `ValidationStatus`), and exposes formatters (`FormatPublicKey`, `FormatFingerprint`) plus `ExportCertificate(cert, format, filename)`. The model never imports `crypto/x509` for anything beyond what this package returns.

The package keeps its own logger that defaults to a no-op (so it never writes to stderr and corrupts the TUI). `PersistentPreRun` calls `certificate.SetLogger(logger.Log)` to route its diagnostics to the same destination as the rest of the app. Validity math (`ValidityPeriodDays`, the expiry bars) works in Unix seconds rather than `time.Duration` to avoid overflow on far-future `NotAfter` dates (the `9999-12-31` no-expiry convention).

### Config & logging

`internal/config` uses viper to read `~/.y509.yaml` (Catppuccin Mocha defaults inline). The whole TUI color palette flows through `config.Theme` → `model.NewStyles` → `model.Styles` and is consumed by both renderers and the `certDelegate`.

`internal/logger` wraps zap. Initialized in `RootCmd.PersistentPreRun`; the optional `--log-file` and `--debug` flags route everything through `logger.Log`.

## Dependabot policy

`.github/dependabot.yml` groups Charm libraries together (`github.com/charmbracelet/*` patterns) so a future v2 → v3 cascade arrives as one coordinated PR. Group rules cover minor/patch only — major bumps come as individual PRs deliberately, so they can be reviewed in isolation. The catch-all `go-minor-patch` group must remain last; Dependabot assigns each dep to the first matching group.
