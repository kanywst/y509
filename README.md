# y509

[![Go Report Card](https://goreportcard.com/badge/github.com/kanywst/y509)](https://goreportcard.com/report/github.com/kanywst/y509)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A terminal user interface (TUI) tool for viewing and analyzing X.509 certificate chains, built with Go using [Bubble Tea](https://github.com/charmbracelet/bubbletea) and [Lip Gloss](https://github.com/charmbracelet/lipgloss).

## Features

- **Intuitive TUI**: Two-pane interface with certificate list and detailed information
- **Command Mode**: k9s-style command interface for detailed certificate inspection
- **Certificate Status**: Color-coded indicators for expired and expiring certificates
- **Detailed Information**: Subject, Issuer, validity, SAN, public key info, SHA256 fingerprint
- **Keyboard Navigation**: Arrow keys for navigation, left/right for pane switching
- **Multiple Input Sources**: Read from files or stdin

## Installation

### Using go install

```bash
go install github.com/kanywst/y509@latest
```

### From Source

```bash
git clone https://github.com/kanywst/y509.git
cd y509
go build -o y509 ./cmd/y509
```

### Using Homebrew (Coming Soon)

```bash
brew install kanywst/tap/y509
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

Press `:` to enter command mode (similar to k9s). Available commands:

| Command | Shortcut | Description |
|---------|----------|-------------|
| `subject` | `s` | Show detailed certificate subject information |
| `issuer` | `i` | Show detailed certificate issuer information |
| `validity` | `v` | Show certificate validity period and status |
| `san` | | Show Subject Alternative Names |
| `fingerprint` | `fp` | Show SHA256 fingerprint |
| `serial` | | Show certificate serial number |
| `pubkey` | `pk` | Show public key information |
| `goto N` | `g N` | Jump to certificate number N |
| `help` | `h` | Show command help |
| `quit` | `q` | Exit command mode |

#### Command Mode Examples

```
:subject          # Show detailed subject information
:s                # Same as above (shortcut)
:validity         # Show validity period with expiration countdown
:san              # Show all Subject Alternative Names
:goto 2           # Jump to certificate #2
:g 1              # Jump to certificate #1 (shortcut)
:help             # Show all available commands
```

In command mode:
- Press `Enter` to execute the command
- Press `ESC` or `Ctrl+C` to exit command mode
- Use `Backspace` to edit the command

## Certificate Status Indicators

- 🟢 **Valid**: Certificate is valid and expires in more than 30 days
- 🟡 **Expiring Soon**: Certificate expires within 30 days
- 🔴 **Expired**: Certificate has already expired

## Demo

![y509 Demo](demo.gif)

*Live demonstration of y509 showing certificate navigation, details view, pane switching, and command mode*

### Recording the Demo

This project includes a [VHS](https://github.com/charmbracelet/vhs) script for recording demonstrations:

```bash
# Install VHS
go install github.com/charmbracelet/vhs@latest

# Record demo
vhs demo.tape

# View the generated GIF
open demo.gif
```

## Examples

### Viewing a Website's Certificate Chain

```bash
# Get certificate chain from a website
echo | openssl s_client -connect github.com:443 -showcerts 2>/dev/null | y509
```

### Analyzing Local Certificate Files

```bash
# View a single certificate
y509 server.crt

# View a certificate chain
y509 fullchain.pem

# View multiple certificates
cat *.crt | y509
```

### Using Command Mode for Detailed Analysis

1. Launch y509 with your certificate file
2. Press `:` to enter command mode
3. Type `subject` to see detailed subject information
4. Press `ESC` to return to normal mode
5. Use `:validity` to check expiration status
6. Use `:san` to view all alternative names

## Project Structure

```
y509/
├── cmd/y509/           # Main application entry point
│   └── main.go
├── pkg/certificate/    # Certificate parsing and analysis
│   ├── certificate.go
│   └── certificate_test.go
├── internal/model/     # TUI model and view logic
│   └── model.go
├── testdata/          # Test data and sample certificates
│   └── demo/
│       └── certs.pem
├── demo.tape          # VHS recording script
├── demo.gif           # Demo animation
├── go.mod
└── README.md
```

## Development

### Prerequisites

- Go 1.19 or later
- Terminal with true color support (recommended)

### Building

```bash
# Build for current platform
go build -o y509 ./cmd/y509

# Build for multiple platforms
GOOS=linux GOARCH=amd64 go build -o y509-linux-amd64 ./cmd/y509
GOOS=darwin GOARCH=amd64 go build -o y509-darwin-amd64 ./cmd/y509
GOOS=windows GOARCH=amd64 go build -o y509-windows-amd64.exe ./cmd/y509
```

### Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run tests with verbose output
go test -v ./pkg/certificate

# Test with sample data
./y509 testdata/demo/certs.pem
```

### Dependencies

- [Bubble Tea](https://github.com/charmbracelet/bubbletea) - TUI framework
- [Lip Gloss](https://github.com/charmbracelet/lipgloss) - Styling library

## Certificate Information Displayed

y509 displays comprehensive certificate information including:

- **Subject**: Certificate subject details (CN, O, OU, C, Province, Locality)
- **Issuer**: Certificate authority information
- **Validity**: Not before/after dates, current status, and time remaining
- **Subject Alternative Names**: DNS names, IP addresses, email addresses
- **Public Key**: Algorithm, key type, and size information
- **SHA256 Fingerprint**: Certificate fingerprint
- **Serial Number**: Certificate serial number

## Use Cases

- **DevOps**: Quickly inspect certificate chains in CI/CD pipelines
- **Security Audits**: Analyze certificate validity and expiration dates
- **Debugging**: Troubleshoot SSL/TLS certificate issues with detailed views
- **Monitoring**: Check certificate status before expiration
- **Learning**: Understand certificate chain structures
- **Certificate Management**: Navigate and analyze multiple certificates efficiently

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for your changes
5. Ensure tests pass (`go test ./...`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Charm](https://charm.sh/) for the excellent TUI libraries
- [Go team](https://golang.org/) for the robust standard library
- [k9s](https://k9scli.io/) for command mode inspiration
- Certificate transparency and security community

## Roadmap

- [x] Command mode for detailed certificate inspection
- [ ] Certificate chain validation
- [ ] Export certificates in various formats (DER, PEM)
- [ ] Certificate comparison mode
- [ ] Integration with certificate transparency logs
- [ ] Plugin system for custom certificate analysis
- [ ] Configuration file support
- [ ] Certificate monitoring and alerting
- [ ] Search and filter functionality

## Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/kanywst/y509/issues) page
2. Create a new issue with detailed information
3. Include your Go version and operating system
4. Provide sample certificate data if relevant (remove sensitive information)

---

**Note**: This tool is for certificate analysis and inspection only. Always verify certificate validity through proper certificate validation mechanisms in production environments.
