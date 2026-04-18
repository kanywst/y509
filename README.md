# y509

[![Go Report Card](https://goreportcard.com/badge/github.com/kanywst/y509)](https://goreportcard.com/report/github.com/kanywst/y509)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Built with Bubble Tea](https://img.shields.io/badge/Built%20with-Bubble%20Tea-B7A0E8.svg)](https://github.com/charmbracelet/bubbletea)

A TUI for analyzing and validating X.509 certificate chains. Built with [Bubble Tea](https://github.com/charmbracelet/bubbletea) and [Lip Gloss](https://github.com/charmbracelet/lipgloss).

![y509 Demo](demo.gif)

## Install

```bash
# Homebrew
brew tap kanywst/y509 https://github.com/kanywst/y509
brew install y509

# Go 1.25+
go install github.com/kanywst/y509@latest
```

## Usage

```bash
y509 cert-chain.pem
openssl s_client -connect example.com:443 -showcerts | y509
```

## Keybindings

| Key | Action |
|:---:|:---|
| `↑/k` `↓/j` | Navigate list |
| `←/h` `→/l` | Switch panes |
| `tab` | Cycle detail tabs |
| `/` | Search |
| `f` | Filter (expired, expiring, valid, self-signed) |
| `v` | Validate certificate |
| `e` | Export certificate |
| `esc` | Clear filter / close popup |
| `?` | Help |
| `q` | Quit |

## Configuration

`~/.y509.yaml` — Catppuccin Mocha theme by default.

```yaml
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

## License

Apache License 2.0
