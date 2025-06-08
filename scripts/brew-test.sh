#!/bin/bash
set -e

# This script verifies the installation of y509 using Homebrew
# Usage: ./brew-test.sh

echo "Testing y509 installation via Homebrew..."

# Check if y509 is installed
if ! brew list y509 &>/dev/null; then
    echo "Error: y509 is not installed via Homebrew"
    exit 1
fi

echo "✓ y509 is installed via Homebrew"

# Get the version
VERSION=$(y509 --version | grep -o "v[0-9]\+\.[0-9]\+\.[0-9]\+")

if [ -z "$VERSION" ]; then
    echo "Error: Could not determine y509 version"
    exit 1
fi

echo "✓ Version check passed: $VERSION"

# Check for man page
if [ ! -f "$(brew --prefix)/share/man/man1/y509.1" ]; then
    echo "Warning: Man page not found"
else
    echo "✓ Man page is installed"
fi

# Check for shell completions
if [ ! -f "$(brew --prefix)/share/bash-completion/completions/y509" ]; then
    echo "Warning: Bash completion not found"
else
    echo "✓ Bash completion is installed"
fi

if [ ! -f "$(brew --prefix)/share/zsh/site-functions/_y509" ]; then
    echo "Warning: Zsh completion not found"
else
    echo "✓ Zsh completion is installed"
fi

echo "All tests passed!"
