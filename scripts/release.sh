#!/bin/bash
set -e

# This script prepares a new release for y509
# Usage: ./release.sh v0.2.0

VERSION=$1

if [ -z "$VERSION" ]; then
    echo "Error: Version number is required"
    echo "Usage: ./release.sh v0.2.0"
    exit 1
fi

# Remove v prefix if present
VERSION_NUM=${VERSION#v}

echo "Preparing release $VERSION..."

# Create release directory
mkdir -p release

# Build binaries for different platforms
echo "Building binaries..."
GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w -X github.com/kanywst/y509/internal/version.Version=$VERSION_NUM" -o "release/y509-$VERSION_NUM-darwin-amd64" ./cmd/y509
GOOS=darwin GOARCH=arm64 go build -ldflags "-s -w -X github.com/kanywst/y509/internal/version.Version=$VERSION_NUM" -o "release/y509-$VERSION_NUM-darwin-arm64" ./cmd/y509
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w -X github.com/kanywst/y509/internal/version.Version=$VERSION_NUM" -o "release/y509-$VERSION_NUM-linux-amd64" ./cmd/y509
GOOS=linux GOARCH=arm64 go build -ldflags "-s -w -X github.com/kanywst/y509/internal/version.Version=$VERSION_NUM" -o "release/y509-$VERSION_NUM-linux-arm64" ./cmd/y509

# Create archives
echo "Creating archives..."
cd release
tar -czf "y509-$VERSION_NUM-darwin-amd64.tar.gz" "y509-$VERSION_NUM-darwin-amd64"
tar -czf "y509-$VERSION_NUM-darwin-arm64.tar.gz" "y509-$VERSION_NUM-darwin-arm64"
tar -czf "y509-$VERSION_NUM-linux-amd64.tar.gz" "y509-$VERSION_NUM-linux-amd64"
tar -czf "y509-$VERSION_NUM-linux-arm64.tar.gz" "y509-$VERSION_NUM-linux-arm64"
cd ..

# Calculate SHA256 hashes
echo "Calculating SHA256 hashes..."
cd release
shasum -a 256 *.tar.gz > "y509-$VERSION_NUM-checksums.txt"
cd ..

# Update homebrew formula
echo "Updating homebrew formula..."
# Update URL in Formula
sed -i '' "s/url \"https:\/\/github.com\/kanywst\/y509\/archive\/refs\/tags\/v.*\.tar\.gz\"/url \"https:\/\/github.com\/kanywst\/y509\/archive\/refs\/tags\/$VERSION.tar.gz\"/" Formula/y509.rb

echo "⚠️ WARNING: The SHA256 hash needs to be updated after creating the GitHub release."
echo "⚠️ You need to update Formula/y509.rb with the correct SHA256 after uploading the release."
echo "⚠️ Run the following command to get the correct SHA256 hash:"
echo "curl -L https://github.com/kanywst/y509/archive/refs/tags/$VERSION.tar.gz | shasum -a 256"

echo "Release preparation complete!"
echo "Files are available in the 'release' directory"
echo "Next steps:"
echo "1. Create a new GitHub release with tag $VERSION"
echo "2. Upload the .tar.gz files and checksums"
echo "3. Get the SHA256 hash of the GitHub source tarball with:"
echo "   curl -L https://github.com/kanywst/y509/archive/refs/tags/$VERSION.tar.gz | shasum -a 256"
echo "4. Update Formula/y509.rb with the correct SHA256 hash"
echo "5. Push the updated homebrew formula"
