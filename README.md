# y509

[![Go Report Card](https://goreportcard.com/badge/github.com/kanywst/y509)](https://goreportcard.com/report/github.com/kanywst/y509)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Built with Bubble Tea](https://img.shields.io/badge/Built%20with-Bubble%20Tea-B7A0E8.svg)](https://github.com/charmbracelet/bubbletea)

A TUI for X.509 certificate chains. It verifies a chain against the system trust store, and — separately — reports how the chain was actually *served*: the missing intermediate, the redundant root, the wrong order. That second question is the one behind "works in the browser, breaks in `curl`", and the one `openssl s_client` leaves you to answer by eye.

Built on the [Charm](https://charm.sh) v2 stack — [Bubble Tea](https://charm.land/bubbletea/v2), [Lip Gloss](https://charm.land/lipgloss/v2), [Bubbles](https://charm.land/bubbles/v2), and [huh](https://charm.land/huh/v2).

![y509 Demo](demo.gif?v=2)

## Install

```bash
# Homebrew (macOS)
brew install kanywst/tap/y509

# FreeBSD
pkg install y509

# Go 1.26+
go install github.com/kanywst/y509/cmd/y509@latest
```

```powershell
# Windows
scoop bucket add kanywst https://github.com/kanywst/scoop-bucket
scoop install kanywst/y509
```

Every [release](https://github.com/kanywst/y509/releases) attaches binaries for
macOS, Linux and Windows — `.tar.gz` for the first two, `.zip` for Windows —
plus `.deb` and `.rpm` packages for Linux, with checksums, cosign signatures and
an SBOM.

On Windows, Scoop is the easy path; otherwise unpack the zip and put `y509.exe`
on your `PATH`. Any terminal that supports ANSI works, and Windows Terminal is
the safe choice. Shell completion comes from `y509 completion powershell`.

On FreeBSD, y509 is [`security/y509`](https://www.freshports.org/security/y509/)
in the ports tree, packaged and maintained there rather than here. Until the
binary package reaches your repository, build it with
`make -C /usr/ports/security/y509 install clean`.

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
y509 ldap.example.com:389 --starttls ldap
y509 db.example.com:3306 --starttls mysql
```

An argument naming an existing file is always read as a file; anything else is
treated as an address. Pass `--connect` to force it. `--starttls` understands
`smtp`, `imap`, `ftp`, `ldap`, `mysql` and `postgres` (`mariadb` and
`postgresql` are accepted as aliases).

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
    the chain stops at a certificate that is not a CA; its issuer "YR2" was
    never sent, so a client that does not chase AIA (curl, Go, Java) cannot
    build a chain
    fetch from: http://yr2.i.lencr.org/
```

Note that the chain *verified* — on macOS the platform verifier fetched the
missing intermediate over the network — and it is still misconfigured. That gap
is the whole point: the check is structural, so it cannot be papered over.

It also reports a redundant root (a root the server should not be sending),
certificates sent out of order, duplicates, and strangers in the bundle.

### Machine-readable output

`--json` writes the whole result to stdout, and nothing else does. The text
report is replaced rather than added to, and the failure message goes to stderr,
so the stream parses even when the check fails. The exit codes are unchanged.

```bash
y509 validate example.com:443 --json | jq .
```

```json
{
  "host": "example.com",
  "trust": {
    "level": "self-anchored",
    "trusted": false,
    "anchor": "Internal Root CA",
    "error": "x509: certificate signed by unknown authority"
  },
  "presentation": {
    "ok": false,
    "findings": [
      {
        "problem": "missing issuer",
        "subject": "*.example.com",
        "detail": "the chain stops at a certificate that is not a CA; its issuer \"YR2\" was never sent, so a client that does not chase AIA (curl, Go, Java) cannot build a chain",
        "fetchUrls": ["http://yr2.i.lencr.org/"]
      }
    ]
  },
  "chain": [{ "index": 0, "commonName": "*.example.com", "daysUntilExpiry": 43, "…": "…" }],
  "connection": {
    "tlsVersion": "TLS 1.3",
    "cipherSuite": "TLS_AES_128_GCM_SHA256",
    "ocspStapled": true
  }
}
```

`connection` is what the handshake revealed rather than what the certificates
say, so it is absent entirely for a file or stdin input. Testing for the key is
how a consumer tells a live check from an offline one.

This exists because the exit code cannot carry the answer. It collapses
`self-anchored` and `broken` into the same non-zero, so a script cannot tell an
internal PKI from a chain that does not link up — and it says nothing at all
about how the chain was served, which is the finding you most likely came for:

```bash
# Fail the build on a chain that verifies but is mis-served.
y509 validate example.com:443 --json | jq -e '.presentation.ok'

# Warn 30 days out, without parsing prose.
y509 validate example.com:443 --json | jq '.chain[0].daysUntilExpiry < 30'

# Find anything still negotiating below TLS 1.2.
y509 validate example.com:443 --json | jq -e '.connection.tlsVersion | test("1\\.[23]$")'
```

`chain` is in the order the certificates were **presented**, not sorted, because
sorting is what destroys the evidence `presentation` reports on. `level` and
`problem` are strings, and `findings` is always an array, never `null`.

### GitHub Actions

The same check as a step. It downloads a release binary, verifies its checksum,
and fails the job on whichever findings you name:

```yaml
- uses: kanywst/y509@v1
  with:
    target: example.com:443
    fail-on: untrusted,mis-served,expiring
    expiry-days: 30
```

The interesting gate is `mis-served`, which catches the chain that *verifies*
and is still broken for `curl`, Go and Java. Nothing else in a normal CI run
looks for it, because the exit code of every other tool says the chain is fine.

| Input | Default | |
| :--- | :--- | :--- |
| `target` | — | host, `host:port`, or a PEM/DER path in the workspace |
| `version` | `latest` | a release tag; pin it for a reproducible check |
| `fail-on` | `untrusted,mis-served` | any of `untrusted`, `mis-served`, `expiring`, or `none` |
| `expiry-days` | `30` | threshold for `expiring` |
| `starttls` | — | `smtp`, `imap`, `ftp`, `ldap`, `mysql`, `postgres` |
| `servername` | — | SNI name, when it differs from the host dialled |
| `roots` | — | PEM file of extra trust anchors, for an internal PKI |
| `no-system-roots` | `false` | trust only `roots` |
| `summary` | `true` | write a report to the job summary |

Outputs: `trust-level`, `trusted`, `presentation-ok`, `days-until-expiry`,
`problems`, and `report` (a path to the full JSON).

Anything not listed under `fail-on` is still reported, as a warning rather than
an error, so `fail-on: none` turns the step into a monitor:

```yaml
on:
  schedule:
    - cron: "0 6 * * *"

jobs:
  certificates:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        host: [www.example.com, api.example.com, smtp.example.com:587]
    steps:
      - uses: kanywst/y509@v1
        with:
          target: ${{ matrix.host }}
          fail-on: untrusted,mis-served,expiring
```

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

The checksum file is signed keyless via GitHub OIDC. Signature and certificate
travel together in one Sigstore bundle, `y509-<version>-checksums.txt.sigstore.json`:

```bash
TAG=v<version>
gh release download "$TAG" -R kanywst/y509 -p '*-checksums.txt*'

cosign verify-blob \
  --bundle "y509-${TAG#v}-checksums.txt.sigstore.json" \
  --certificate-identity-regexp 'https://github.com/kanywst/y509/.github/workflows/release.yml@refs/tags/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "y509-${TAG#v}-checksums.txt"

sha256sum -c "y509-${TAG#v}-checksums.txt" --ignore-missing
```

Releases up to and including v1.0.2 predate the bundle format and ship a `.sig`
plus a `.pem` instead. Verify those with `--signature` and `--certificate`, and
with a cosign 2.x binary, since cosign 3.x dropped both flags.

## License

Apache License 2.0
