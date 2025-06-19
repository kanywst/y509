# y509

[![Go Report Card](https://goreportcard.com/badge/github.com/kanywst/y509)](https://goreportcard.com/report/github.com/kanywst/y509)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A terminal user interface (TUI) tool for viewing and analyzing X.509 certificate chains, built with Go using [Bubble Tea](https://github.com/charmbracelet/bubbletea) and [Lip Gloss](https://github.com/charmbracelet/lipgloss).

![y509 Demo](demo.gif)

## Features

- **Intuitive TUI**: Two-pane interface with certificate list and detailed information
- **Certificate Chain Validation**: Comprehensive chain validation with detailed error reporting
- **Search & Filter**: Search certificates by CN, organization, DNS names, or filter by status
- **Export Functionality**: Export certificates in PEM or DER format
- **Certificate Status**: Color-coded indicators for expired and expiring certificates
- **Detailed Certificate Information**: Subject, Issuer, validity, SAN, SHA256 fingerprint, serial number
- **Multiple Input Sources**: Read from files or stdin

## Installation

### Using Homebrew (macOS)

```bash
brew tap kanywst/y509 https://github.com/kanywst/y509
brew install y509
```

### Using go install

```bash
go install github.com/kanywst/y509@latest
```

### Building from source

```bash
git clone https://github.com/kanywst/y509.git
cd y509
go build -o y509 ./cmd/y509
```

## Usage

### Basic Usage

```bash
# Read from file
y509 path/to/certificate-chain.pem

# Read from stdin
cat certificate-chain.pem | y509
openssl s_client -connect example.com:443 -showcerts | y509
```

### Keyboard Controls

| Key | Action |
|-----|--------|
| `↑` / `k` | Navigate up in certificate list |
| `↓` / `j` | Navigate down in certificate list |
| `←` / `h` | Switch to left pane (certificate list) |
| `→` / `l` | Switch to right pane (certificate details) |
| `:` | Enter command mode |
| `q` / `Ctrl+C` | Quit application |

### Command Mode

Press `:` to enter command mode. Available commands:

| Command | Description |
|---------|-------------|
| `subject` | Show detailed certificate subject information |
| `issuer` | Show detailed certificate issuer information |
| `validity` | Show certificate validity period and status |
| `san` | Show Subject Alternative Names |
| `fingerprint` | Show SHA256 fingerprint |
| `serial` | Show certificate serial number |
| `pubkey` | Show public key information |
| `validate` | Validate certificate chain |
| `search <query>` | Search certificates by CN, organization, DNS names |
| `filter expired` | Show only expired certificates |
| `filter expiring` | Show only expiring certificates (within 30 days) |
| `export pem <filename>` | Export current certificate as PEM format |
| `export der <filename>` | Export current certificate as DER format |
| `help` | Show command help |
| `quit` | Exit command mode |

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
