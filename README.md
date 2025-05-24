# y509

[![Go Report Card](https://goreportcard.com/badge/github.com/kanywst/y509)](https://goreportcard.com/report/github.com/kanywst/y509)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A terminal user interface (TUI) tool for viewing and analyzing X.509 certificate chains, built with Go using [Bubble Tea](https://github.com/charmbracelet/bubbletea) and [Lip Gloss](https://github.com/charmbracelet/lipgloss).

![y509 Demo](demo.gif)

*Live demonstration of y509 showing certificate navigation, details view, pane switching, command mode, chain validation, search/filter functionality, and export capabilities*

## Features

- **Intuitive TUI**: Two-pane interface with certificate list and detailed information
- **Command Mode**: k9s-style command interface for detailed certificate inspection
- **Certificate Chain Validation**: Comprehensive chain validation with detailed error reporting
- **Search & Filter**: Search certificates by CN, organization, DNS names, or filter by status
- **Export Functionality**: Export certificates in PEM or DER format
- **Certificate Status**: Color-coded indicators for expired and expiring certificates
- **Detailed Public Key Information**: RSA key sizes (RSA2048, RSA4096), ECDSA curves (P-256, P-384, P-521), modulus size, public exponent
- **Comprehensive Certificate Details**: Subject, Issuer, validity, SAN, SHA256 fingerprint, serial number
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

#### Certificate Information Commands

| Command | Shortcut | Description |
|---------|----------|-------------|
| `subject` | `s` | Show detailed certificate subject information |
| `issuer` | `i` | Show detailed certificate issuer information |
| `validity` | `v` | Show certificate validity period and status |
| `san` | | Show Subject Alternative Names |
| `fingerprint` | `fp` | Show SHA256 fingerprint |
| `serial` | | Show certificate serial number |
| `pubkey` | `pk` | Show public key information |

#### Navigation Commands

| Command | Shortcut | Description |
|---------|----------|-------------|
| `goto N` | `g N` | Jump to certificate number N |

#### Chain Operations

| Command | Shortcut | Description |
|---------|----------|-------------|
| `validate` | `val` | Validate certificate chain |

#### Search & Filter Commands

| Command | Description |
|---------|-------------|
| `search <query>` | Search certificates by CN, organization, DNS names, or issuer |
| `filter expired` | Show only expired certificates |
| `filter expiring` | Show only expiring certificates (within 30 days) |
| `filter valid` | Show only valid certificates |
| `filter self-signed` | Show only self-signed certificates |
| `reset` | Reset search/filter to show all certificates |

#### Export Commands

| Command | Description |
|---------|-------------|
| `export pem <filename>` | Export current certificate as PEM format |
| `export der <filename>` | Export current certificate as DER format |

#### Other Commands

| Command | Shortcut | Description |
|---------|----------|-------------|
| `help` | `h` | Show command help |
| `quit` | `q` | Exit command mode |

### Command Mode Examples

```bash
# Certificate information
:subject          # Show detailed subject information
:s                # Same as above (shortcut)
:validity         # Show validity period with expiration countdown
:san              # Show all Subject Alternative Names

# Navigation
:goto 2           # Jump to certificate #2
:g 1              # Jump to certificate #1 (shortcut)

# Chain validation
:validate         # Validate the entire certificate chain
:val              # Same as above (shortcut)

# Search and filter
:search github    # Search for certificates containing "github"
:filter expired   # Show only expired certificates
:filter expiring  # Show certificates expiring within 30 days
:reset            # Reset to show all certificates

# Export
:export pem cert1.pem    # Export current certificate as PEM
:export der cert1.der    # Export current certificate as DER

# Help
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

### Advanced Usage with Command Mode

#### Certificate Chain Validation
1. Launch y509 with your certificate file
2. Press `:` to enter command mode
3. Type `validate` to check the entire chain
4. Review validation results, errors, and warnings

#### Search and Filter Operations
```bash
# Search for specific certificates
:search example.com       # Find certificates for example.com
:search "Let's Encrypt"   # Find Let's Encrypt certificates
:search 192.168.1.1       # Find certificates with specific IP

# Filter by certificate status
:filter expired           # Show only expired certificates
:filter expiring          # Show certificates expiring soon
:filter valid             # Show only valid certificates
:filter self-signed       # Show self-signed certificates

# Reset filters
:reset                    # Show all certificates again
```

#### Export Certificates
```bash
# Export in different formats
:export pem server.pem    # Export as PEM format
:export der server.der    # Export as DER format
```

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
- **Public Key**: Detailed algorithm information including:
  - **RSA Keys**: Type (RSA2048, RSA4096), key size in bits, modulus size, public exponent
  - **ECDSA Keys**: Curve name (P-256, P-384, P-521), key size, NIST standard identification
  - **Key Specifications**: Comprehensive technical details for security analysis
- **SHA256 Fingerprint**: Certificate fingerprint
- **Serial Number**: Certificate serial number
- **Chain Validation**: Signature verification, expiration checks, and warnings

## Use Cases

- **DevOps**: Quickly inspect certificate chains in CI/CD pipelines
- **Security Audits**: Analyze certificate validity and expiration dates
- **Debugging**: Troubleshoot SSL/TLS certificate issues with detailed views
- **Monitoring**: Check certificate status before expiration
- **Learning**: Understand certificate chain structures
- **Certificate Management**: Navigate and analyze multiple certificates efficiently
- **Compliance**: Validate certificate chains for security compliance
- **Incident Response**: Quickly identify problematic certificates in a chain

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
- [x] Certificate chain validation
- [x] Export certificates in various formats (DER, PEM)
- [x] Search and filter functionality
- [ ] Certificate comparison mode
- [ ] Integration with certificate transparency logs
- [ ] Plugin system for custom certificate analysis
- [ ] Configuration file support
- [ ] Certificate monitoring and alerting

## Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/kanywst/y509/issues) page
2. Create a new issue with detailed information
3. Include your Go version and operating system
4. Provide sample certificate data if relevant (remove sensitive information)

---

**Note**: This tool is for certificate analysis and inspection only. Always verify certificate validity through proper certificate validation mechanisms in production environments.
