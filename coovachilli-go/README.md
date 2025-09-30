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
