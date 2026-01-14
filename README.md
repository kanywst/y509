# y509

[![Go Report Card](https://goreportcard.com/badge/github.com/kanywst/y509)](https://goreportcard.com/report/github.com/kanywst/y509)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Built with Bubble Tea](https://img.shields.io/badge/Built%20with-Bubble%20Tea-B7A0E8.svg)](https://github.com/charmbracelet/bubbletea)

`y509` is a TUI tool designed to make analyzing and validating X.509 certificate chains painless. Built with Go, [Bubble Tea](https://github.com/charmbracelet/bubbletea), and [Lip Gloss](https://github.com/charmbracelet/lipgloss).

![y509 Demo](demo.gif)

## Features

- **Performance First**: Powered by a custom viewport rendering engine. Handles thousands of certificates smoothly with O(n) complexity.
- **Popup UI**: Intuitive modal-driven search and filtering. No more complex command-line flags for basic tasks.
- **Smart Validation**: Validates individual certificates against the entire loaded pool. Automatically detects trust anchors.
- **Deep Search**: Instant search across Subject, Issuer, and SANs (DNS names).
- **Themeable**: Fully customizable colors via YAML. Ships with a beautiful "Catppuccin" inspired default.
- **🏁 Zebra Striping**: Clean, alternating row colors for perfect readability in long lists.
- **Multi-Source**: Read from files, directories, or pipe directly from `stdin`.

## Installation

### macOS / Linux (Homebrew)

```bash
brew tap kanywst/y509 https://github.com/kanywst/y509
brew install y509
```

### Go (Version 1.25+)

```bash
go install github.com/kanywst/y509@latest
```

## Usage

### Quick Start

```bash
# Open a certificate file
y509 cert-chain.pem

# Pipe from OpenSSL or other tools
openssl s_client -connect example.com:443 -showcerts | y509

# Run with debug logging
y509 --debug certs.pem
```

### Keyboard Controls

|    Key    |                          Action                          |
| :-------: | :------------------------------------------------------: |
| `↑` / `k` |                Navigate up / Scroll list                 |
| `↓` / `j` |               Navigate down / Scroll list                |
| `←` / `h` |                Switch to Certificate List                |
| `→` / `l` |                  Switch to Details Pane                  |
|   `tab`   |    Cycle through Details Tabs (Subject, Issuer, etc.)    |
|    `/`    |                     **Search** popup                     |
|    `f`    | **Filter** popup (expired, expiring, valid, self-signed) |
|    `v`    |            **Validate** selected certificate             |
|    `e`    |         **Export** selected certificate to file          |
|   `esc`   |            Clear search/filter or close popup            |
|    `?`    |                     Toggle Help view                     |
|    `q`    |                     Quit application                     |

## Configuration

`y509` looks for a configuration file at `~/.y509.yaml`.

```yaml
theme:
  text: "252"
  border: "240"
  border_focus: "62"
  status_bar: "62"
  status_bar_text: "230"
  highlight: "62"
  highlight_text: "230"
  highlight_dim: "238"
  list_row_alt: "235" # Zebra striping color
  status_valid: "40"
  status_warning: "220"
  status_expired: "196"
  title: "aqua"
```

## Development

We use Go 1.25+ tools.

```bash
make build      # Build with version info
make test       # Run test suite
make lint       # Run golangci-lint (via go tool)
make vulncheck  # Run govulncheck (via go tool)
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
