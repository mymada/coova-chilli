# ---- Builder Stage ----
# Use an official Go runtime as a parent image
FROM golang:1.21-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Define build-time variables for cross-compilation
ARG TARGET_OS=linux
ARG TARGET_ARCH=amd64

# Install build dependencies
# gopacket requires libpcap to be installed
# gcc-arm-linux-gnueabihf is needed for cross-compiling to ARM
RUN apk add --no-cache gcc musl-dev libpcap-dev file gcc-arm-linux-gnueabihf

# Copy go mod and sum files to download dependencies first
# This leverages Docker's layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the local package files to the container's workspace
COPY . .

# Build the CoovaChilli-Go binary using the build script
RUN ./build.sh ${TARGET_OS} ${TARGET_ARCH}

# ---- Final Stage ----
# Use a lightweight, secure base image
FROM alpine:latest

ARG TARGET_OS=linux
ARG TARGET_ARCH=amd64

# Install runtime dependencies
# libpcap is needed for the compiled binary to run
RUN apk add --no-cache libpcap

# Set the working directory
WORKDIR /app

# Copy the built binary from the builder stage
COPY --from=builder /app/dist/coovachilli_${TARGET_OS}_${TARGET_ARCH} ./coovachilli

# Copy the default configuration file
COPY config.yaml .

# Expose ports that CoovaChilli-Go might use
# 8080: UAM Port
# 1812: RADIUS Auth Port
# 1813: RADIUS Acct Port
# 3799: RADIUS CoA Port
# 9090: Metrics Port
# 8081: Admin API Port
EXPOSE 8080 1812/udp 1813/udp 3799/udp 9090 8081

# Set the entrypoint for the container
# The application will be run with the default config.yaml
ENTRYPOINT ["./coovachilli"]

# The default command can be overridden at runtime
CMD ["--config", "config.yaml"]