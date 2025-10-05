#!/bin/sh

# This script builds the CoovaChilli-Go application for a specific OS and architecture.
# Usage: ./build.sh <os> <arch>
# Example: ./build.sh linux amd64
# Example for Raspberry Pi: ./build.sh linux arm

set -e # Exit immediately if a command exits with a non-zero status.

# --- Parameters ---
TARGET_OS=${1:-linux}
TARGET_ARCH=${2:-amd64}
OUTPUT_DIR="dist"
BINARY_NAME="coovachilli"

# --- Build ---
echo "Building for ${TARGET_OS}/${TARGET_ARCH}..."

# Set environment variables for cross-compilation
export GOOS=${TARGET_OS}
export GOARCH=${TARGET_ARCH}
# CGO_ENABLED=1 is required for gopacket
export CGO_ENABLED=1

# When cross-compiling, the Go toolchain will automatically select the correct C compiler
# (e.g., arm-linux-gnueabihf-gcc) if it's available in the PATH.
# The Dockerfile ensures the required compilers are installed.

# Create the output directory if it doesn't exist
mkdir -p ${OUTPUT_DIR}

# Build the binary
go build -o "${OUTPUT_DIR}/${BINARY_NAME}_${TARGET_OS}_${TARGET_ARCH}" -ldflags="-s -w" ./cmd/coovachilli

echo "Build successful!"
echo "Binary created at: ${OUTPUT_DIR}/${BINARY_NAME}_${TARGET_OS}_${TARGET_ARCH}"

# Make the script executable
chmod +x "${OUTPUT_DIR}/${BINARY_NAME}_${TARGET_OS}_${TARGET_ARCH}"

# --- Verification ---
echo "Verifying binary architecture..."
file "${OUTPUT_DIR}/${BINARY_NAME}_${TARGET_OS}_${TARGET_ARCH}"