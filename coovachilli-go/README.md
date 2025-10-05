# CoovaChilli-Go

This project is a complete rewrite of the CoovaChilli captive portal in modern Go. It is designed to be a high-performance, dual-stack (IPv4/IPv6) software access controller.

## Architecture

CoovaChilli-Go is built with a modern, modular architecture inspired by the `coovachilli-rust` project. It leverages Go's native concurrency features (goroutines and channels) to create a highly asynchronous, event-driven system.

The project is divided into several packages, each with a specific responsibility:

*   `cmd/coovachilli`: The main application entry point.
*   `pkg/config`: Configuration loading and management.
*   `pkg/core`: Core data structures like `Session` and `SessionManager`.
*   `pkg/session`: Session management logic.
*   `pkg/dhcp`: DHCPv4 and DHCPv6 server logic.
*   `pkg/radius`: RADIUS client logic for authentication and accounting.
*   `pkg/tun`: TUN/TAP interface handling for both IPv4 and IPv6.
*   `pkg/http`: The captive portal HTTP server.
*   `pkg/firewall`: Firewall interaction logic (e.g., using `nftables` or `iptables`).

## Features

*   **Dual-Stack (IPv4/IPv6)**: Full support for both IPv4 and IPv6 clients.
*   **High Performance**: Built with Go's high-performance networking and concurrency features.
*   **Modular Design**: A clean, modular architecture makes the project easy to understand, maintain, and extend.
*   **Dynamic Configuration**: Supports live reloading of the configuration without service interruption.
*   **RADIUS Support**: Full support for RADIUS authentication, authorization, and accounting.
*   **Captive Portal**: A built-in HTTP server for serving the captive portal page.
*   **Firewall Management**: Manages firewall rules to control client access.
*   **High Availability (Clustering)**: Active/Standby failover to prevent service interruptions.

## High Availability (Clustering)

The clustering feature allows you to run multiple CoovaChilli-Go instances in a high-availability setup. It operates in an Active/Standby model, where one node actively handles all traffic while others wait to take over in case of a failure.

**How it works:**
- **Communication**: Nodes communicate over a dedicated network interface using encrypted raw Ethernet frames with a custom EtherType (`0x888F`). The communication is encrypted using Blowfish to ensure security.
- **Failover**: If the `ACTIVE` node goes offline (detected by a lack of heartbeats), the `STANDBY` node with the lowest `peerid` is automatically elected as the new active node.
- **State**: When a node is in `STANDBY` state, it does not process any client traffic from the TUN interface, making it a passive listener until it becomes active.

**Configuration:**
To enable clustering, add the following section to your `config.yaml`:

```yaml
cluster:
  enabled: true
  peerid: 0  # A unique ID for this node (0-7)
  peerkey: "your-secret-key" # A shared secret for encryption
  interface: "eth1" # The dedicated interface for cluster communication
```

## Content Filtering (SNI)

The application supports Layer 7 content filtering for authenticated users by inspecting the Server Name Indication (SNI) in TLS `ClientHello` messages. This allows you to block access to specific HTTPS websites without needing to perform full TLS decryption.

**How it works:**
- When an authenticated user attempts to connect to an HTTPS site, the application inspects the initial TLS handshake.
- It extracts the requested domain name (SNI) from the `ClientHello` message.
- If the domain is found in the SNI blocklist, the packet is dropped, preventing the TLS session from being established.

**Configuration:**
To enable SNI filtering, add the following section to your `config.yaml`:
```yaml
l7filtering:
  sni_filtering_enabled: true
  sni_blocklist_path: "/path/to/your/sni_blocklist.txt"
```
The `sni_blocklist.txt` file should contain one domain per line.

## Getting Started

### Prerequisites

*   **Go**: Version 1.25.1 or later.
*   **C Compiler**: Required for some Go dependencies.
*   **libpcap**: The packet capture library.

On Debian-based systems (like Ubuntu), you can install all prerequisites with:

```bash
sudo apt-get update && sudo apt-get install -y golang-go build-essential libpcap-dev
```

### Building

1.  Navigate to the Go application directory:
    ```bash
    cd coovachilli-go
    ```

2.  Build the binary:
    ```bash
    go build ./cmd/coovachilli
    ```
    This will create an executable file named `coovachilli` in the current directory (`coovachilli-go/`).

### Running

1.  **Configuration**: Before running, you may need to edit `config.yaml`. At a minimum, ensure the `dhcpif` setting matches the name of your LAN interface (e.g., `eth1`, `enp0s8`).

2.  **Execution**: Run the application with `sudo` from within the `coovachilli-go` directory:
    ```bash
    sudo ./coovachilli
    ```
    The application needs `sudo` because it requires elevated privileges to create TUN interfaces and manage firewall rules.

## Configuration

The application is configured using a YAML file (`config.yaml` by default). However, for cloud-native and containerized deployments, all configuration options can be overridden with environment variables.

**Priority Order:**
1.  Environment Variables (highest priority)
2.  Values from `config.yaml` file (lowest priority)

Environment variables must be prefixed with `COOVACHILLI_`. For nested configuration keys, the path is joined with an underscore.

**Example:**

To override the logging level defined in `config.yaml`, you can set the following environment variable:
```bash
export COOVACHILLI_LOGGING_LEVEL=debug
```
This corresponds to the `level` key inside the `logging` section.

## Cross-Compilation with Docker

This project includes a multi-stage `Dockerfile` and a build script to facilitate building for different architectures, such as `arm` for Raspberry Pi devices. This is the recommended method for creating builds for production or for different platforms.

**Prerequisites:**
- Docker installed
- The `docker buildx` command, which is included in modern Docker installations.

**Usage:**

To build for a specific architecture, use the `docker build` command with the `--platform` and `--build-arg` flags. For example, to build for `linux/arm/v7`:

```bash
docker build --platform linux/arm/v7 \
  --build-arg TARGET_OS=linux \
  --build-arg TARGET_ARCH=arm \
  -t coovachilli-go:arm-latest .
```

This will produce a Docker image tagged `coovachilli-go:arm-latest` containing the application binary compiled for ARMv7.

**Note on Native Cross-Compilation Issues:**
During development, attempts to set up a native cross-compilation environment on a standard Debian/Ubuntu `amd64` host (using `gcc-arm-linux-gnueabihf` and `libpcap-dev:armhf`) were unsuccessful due to persistent `apt` repository configuration conflicts. The Docker-based approach is the recommended and most reliable method for building the application for different platforms.
