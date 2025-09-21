# CoovaChilli-Rust

This is a rewrite of the CoovaChilli captive portal in Rust. The goal is to create a more modern, secure, and maintainable implementation of the original C-based project.

This port is functional and implements many of the core features of CoovaChilli, including DHCP, RADIUS (PAP, EAP-MD5, EAP-MSCHAPv2), UAM, and session management.

## Project Structure

The project is organized as a Rust workspace with the following crates:

- `chilli-core`: Contains the core logic, data structures, and configuration management for the application.
- `chilli-net`: Provides the networking components, including the TUN/TAP interface, DHCP server, and RADIUS client.
- `chilli-http`: Implements the UAM/captive portal HTTP server using the `axum` framework and the `Tera` templating engine.
- `chilli-bin`: The main binary crate that integrates all the other components and runs the application.
- `chilli-query`: A command-line tool to query the state of the main daemon.
- `chilli-ipc`: Handles Inter-Process Communication between the daemon and query tool.

## Web Interface

The web interface for the captive portal is built using the `axum` web framework and the `Tera` templating engine. This modern approach replaces the traditional CGI scripts used in the original CoovaChilli, providing better performance, security, and easier customization.

Portal pages are located in the `chilli-http/templates` directory. You can customize the look and feel of the portal by editing these HTML files. The templates use Tera's syntax for dynamic content.

## Building

To build the project, you will need to have Rust and Cargo installed. You can then build the entire workspace by running the following command from the `coovachilli-rust` directory:

```bash
cargo build --workspace
```

## Testing

The project includes a suite of unit and integration tests. To run all tests, use the following command from the `coovachilli-rust` directory:

```bash
cargo test --workspace
```

## Running

To run the application, you will need to create a `chilli.toml` configuration file. An example configuration file can be found in `chilli-core/tests/chilli.toml`.

You can then run the application with the following command:

```bash
# You will likely need to run this with sudo to allow for TUN device creation
# and firewall rule manipulation.
sudo cargo run -p chilli-bin -- --config-file /path/to/your/chilli.toml
```

## Feature Status

- **Working:**
  - DHCP Server
  - RADIUS Client (PAP, EAP-MD5, EAP-MSCHAPv2)
  - TUN device integration
  - Session Management (including basic quota support)
  - HTTP UAM Server (for captive portal redirect)
  - Command Socket for IPC

- **Disabled / To-Do:**
  - **MS-CHAPv1:** This legacy authentication protocol has been disabled due to cryptographic dependency issues and its known security vulnerabilities.
  - **UAM Authentication Flow:** The integration test for the full web-based login flow is currently disabled as the feature is incomplete.

## Contributing

Contributions are welcome! Please feel free to open an issue or submit a pull request.
