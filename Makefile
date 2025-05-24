# Build variables
BINARY_NAME=y509
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT?=$(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_DATE?=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Go build flags
LDFLAGS=-ldflags "-X github.com/kanywst/y509/internal/version.Version=$(VERSION) \
                  -X github.com/kanywst/y509/internal/version.GitCommit=$(GIT_COMMIT) \
                  -X github.com/kanywst/y509/internal/version.BuildDate=$(BUILD_DATE)"

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build:
	go build $(LDFLAGS) -o $(BINARY_NAME) ./cmd/y509

# Build for development (without version info)
.PHONY: build-dev
build-dev:
	go build -o $(BINARY_NAME) ./cmd/y509

# Install the binary
.PHONY: install
install:
	go install $(LDFLAGS) ./cmd/y509

# Run tests
.PHONY: test
test:
	go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	go test -cover ./...

# Clean build artifacts
.PHONY: clean
clean:
	rm -f $(BINARY_NAME)
	go clean

# Build for multiple platforms
.PHONY: build-all
build-all:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 ./cmd/y509
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-darwin-amd64 ./cmd/y509
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY_NAME)-darwin-arm64 ./cmd/y509
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY_NAME)-windows-amd64.exe ./cmd/y509

# Create a release
.PHONY: release
release: clean test build-all

# Show version info
.PHONY: version
version:
	@echo "Version: $(VERSION)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Build Date: $(BUILD_DATE)"

# Development helpers
.PHONY: run
run: build-dev
	./$(BINARY_NAME) testdata/demo/certs.pem

.PHONY: demo
demo: build-dev
	./$(BINARY_NAME) testdata/demo/certs.pem

# Format code
.PHONY: fmt
fmt:
	go fmt ./...

# Lint code
.PHONY: lint
lint:
	golangci-lint run

# Tidy dependencies
.PHONY: tidy
tidy:
	go mod tidy

# Help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build        - Build the binary with version info"
	@echo "  build-dev    - Build the binary without version info (faster)"
	@echo "  install      - Install the binary with version info"
	@echo "  test         - Run tests"
	@echo "  test-coverage- Run tests with coverage"
	@echo "  clean        - Clean build artifacts"
	@echo "  build-all    - Build for multiple platforms"
	@echo "  release      - Create a release (clean, test, build-all)"
	@echo "  version      - Show version information"
	@echo "  run          - Build and run with test data"
	@echo "  demo         - Same as run"
	@echo "  fmt          - Format code"
	@echo "  lint         - Lint code"
	@echo "  tidy         - Tidy dependencies"
	@echo "  help         - Show this help"
