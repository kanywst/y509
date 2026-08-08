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

# Generate the demo certificate chain. Not committed, since its baked-in
# dates would go stale (the "expiring" leaf eventually becomes "expired").
.PHONY: demo-certs
demo-certs:
	@go run scripts/gen_demo_certs.go

# Run tests
.PHONY: test
test: demo-certs
	go test -v $(GOTEST_ARGS) ./...

# Run tests with JSON output (useful for CI)
.PHONY: test-json
test-json: demo-certs
	@go test -v -json $(GOTEST_ARGS) ./...

# Run tests with coverage and fail if it slips below the threshold. Without a
# gate the number only ever drifts down, one untested branch at a time.
COVERAGE_THRESHOLD ?= 80.0

.PHONY: test-coverage
test-coverage: demo-certs
	go test -coverprofile=coverage.out -covermode=atomic ./...
	@$(MAKE) --no-print-directory check-coverage

# Split out so the gate can be re-run against an existing profile, and so every
# way of not knowing the coverage is an error. A gate that fails open is worse
# than no gate: it reads as protection while providing none.
.PHONY: check-coverage
check-coverage:
	@case '$(COVERAGE_THRESHOLD)' in \
		''|*[!0-9.]*|*.*.*) bad=1 ;; \
		*[0-9]*) bad= ;; \
		*) bad=1 ;; \
	esac; \
	if [ -n "$$bad" ]; then \
		echo "COVERAGE_THRESHOLD must be a number, got '$(COVERAGE_THRESHOLD)'" >&2; exit 1; \
	fi; \
	summary=$$(go tool cover -func=coverage.out) || { \
		echo "go tool cover failed to read coverage.out" >&2; exit 1; }; \
	total=$$(printf '%s\n' "$$summary" | awk '/^total:/ { sub(/%$$/, "", $$3); print $$3 }'); \
	if [ -z "$$total" ]; then \
		echo "no total line in the coverage summary" >&2; exit 1; \
	fi; \
	if awk -v total="$$total" -v min='$(COVERAGE_THRESHOLD)' 'BEGIN { exit !(total + 0 < min + 0) }'; then \
		echo "coverage $$total% is below the $(COVERAGE_THRESHOLD)% threshold" >&2; exit 1; \
	fi; \
	echo "coverage $$total% meets the $(COVERAGE_THRESHOLD)% threshold"

# Clean build artifacts
.PHONY: clean
clean:
	rm -f $(BINARY_NAME)
	rm -f testdata/demo/certs.pem
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
run: build-dev demo-certs
	./$(BINARY_NAME) testdata/demo/certs.pem

.PHONY: demo
demo: build-dev demo-certs
	./$(BINARY_NAME) testdata/demo/certs.pem

# Format code
.PHONY: fmt
fmt:
	go fmt ./...

# Lint code
.PHONY: lint
lint:
	go tool golangci-lint run ./...

# Vulnerability check
.PHONY: vulncheck
vulncheck:
	go tool govulncheck ./...

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
