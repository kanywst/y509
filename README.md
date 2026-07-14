# y509

[![Go Report Card](https://goreportcard.com/badge/github.com/kanywst/y509)](https://goreportcard.com/report/github.com/kanywst/y509)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Built with Bubble Tea](https://img.shields.io/badge/Built%20with-Bubble%20Tea-B7A0E8.svg)](https://github.com/charmbracelet/bubbletea)

A TUI for analyzing and validating X.509 certificate chains. Built on the [Charm](https://charm.sh) v2 stack — [Bubble Tea](https://charm.land/bubbletea/v2), [Lip Gloss](https://charm.land/lipgloss/v2), [Bubbles](https://charm.land/bubbles/v2), and [huh](https://charm.land/huh/v2).

![y509 Demo](demo.gif?v=2)

## Install

```bash
# Homebrew (macOS)
brew install kanywst/tap/y509

# Go 1.26+
go install github.com/kanywst/y509/cmd/y509@latest
```

Every [release](https://github.com/kanywst/y509/releases) attaches binaries for
macOS and Linux, plus `.deb` and `.rpm` packages for Linux, with checksums,
cosign signatures and an SBOM.

## Usage

```bash
y509 cert-chain.pem                       # a file (PEM or DER)
y509 example.com:443                      # a live server
y509 smtp.example.com:587 --starttls smtp # ...behind STARTTLS
cat chain.pem | y509                      # stdin
```

### Talking to a live server

```bash
y509 example.com:443
y509 --connect 10.0.0.1:8443 --servername api.internal
y509 db.example.com:5432 --starttls postgres
```

An argument naming an existing file is always read as a file; anything else is
treated as an address. Pass `--connect` to force it. `--starttls` understands
`smtp`, `imap` and `postgres`.

The handshake deliberately verifies nothing, because a chain that fails to
verify is usually the reason you came. Certificates come back **in the order the
server sent them**, which is not necessarily a valid chain — a server shipping
its root, or omitting an intermediate, is the classic "works in the browser,
breaks in curl" bug.

### Validating from a script

`validate` verifies against the system trust store and exits non-zero on
anything a TLS client would reject, so it can gate CI:

```bash
y509 validate chain.pem                        # 0 = trusted
y509 validate example.com:443                  # also checks the hostname
y509 validate chain.pem --roots internal-ca.pem
```

| Outcome | Exit | Meaning |
| :--- | :--: | :--- |
| trusted | 0 | verifies against the trust anchors |
| self-anchored | 1 | links up, but its root is not trusted (an internal PKI, or a missing root) |
| broken | 1 | does not link up: expired, bad signature, missing issuer, wrong hostname |

### How the chain was served

Verifying a chain and *serving it correctly* are different questions, and y509
answers both. A server can present a chain that your browser accepts and that
`curl` refuses — because browsers chase the AIA URL to fetch a missing
intermediate and `curl`, Go and Java do not.

y509 reports that separately, from what was actually sent:

```text
$ y509 validate incomplete-chain.badssl.com:443
✅ Certificate chain is valid.
Trust anchor: ISRG Root X1

Chain as presented:
  • missing issuer: *.badssl.com
    the chain stops at a certificate that is not a CA; its issuer "R13" was
    never sent, so a client that does not chase AIA (curl, Go, Java) cannot
    build a chain
    fetch from: http://r13.i.lencr.org/
```

Note that the chain *verified* — on macOS the platform verifier fetched the
missing intermediate over the network — and it is still misconfigured. That gap
is the whole point: the check is structural, so it cannot be papered over.

It also reports a redundant root (a root the server should not be sending),
certificates sent out of order, duplicates, and strangers in the bundle.

## Keybindings

|     Key     | Action                                         |
| :---------: | :--------------------------------------------- |
| `↑/k` `↓/j` | Navigate list                                  |
| `←/h` `→/l` | Switch panes                                   |
|    `tab`    | Cycle detail tabs                              |
|     `/`     | Search                                         |
|     `f`     | Filter (expired, expiring, valid, self-signed) |
|     `v`     | Validate certificate                           |
|     `e`     | Export certificate (filename + format form)    |
|     `y`     | Copy selected certificate as PEM (OSC52)       |
|    `esc`    | Clear filter / close popup                     |
|     `?`     | Help                                           |
|     `q`     | Quit                                           |

## Configuration

`~/.y509.yaml` — Catppuccin Mocha theme by default.

```yaml
# Days before expiry to flag a certificate as "expiring soon" (default 30).
# Lower this as CA/Browser Forum maximum lifetimes shrink (200 days in 2026).
expiry_warning_days: 30

theme:
  text: "#cdd6f4"
  border: "#45475a"
  border_focus: "#89b4fa"
  background: "#1e1e2e"
  status_bar: "#181825"
  status_bar_text: "#cdd6f4"
  command_bar: "#313244"
  command_bar_text: "#cdd6f4"
  error: "#f38ba8"
  highlight: "#89b4fa"
  highlight_text: "#1e1e2e"
  highlight_dim: "#313244"
  status_valid: "#a6e3a1"
  status_warning: "#f9e2af"
  status_expired: "#f38ba8"
  title: "#89dceb"
  section_title: "#b4befe"
  detail_key: "#9399b2"
  list_row_alt: "#181825"
```

## Development

```bash
make build       # Build with version info
make test        # Run tests
make lint        # Run golangci-lint
make vulncheck   # Run govulncheck
```

## Verifying releases

Release archives carry Sigstore-signed checksums, a CycloneDX SBOM, and SLSA
build provenance. Verify provenance with the GitHub CLI:

```bash
gh attestation verify y509-<version>-<os>-<arch>.tar.gz -R kanywst/y509
```

## License

Apache License 2.0
