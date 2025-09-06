# CoovaChilli-Rust

This is a rewrite of the CoovaChilli captive portal in Rust. The goal is to create a more modern, secure, and maintainable implementation of the original C-based project.

## Project Structure

The project is organized as a Rust workspace with the following crates:

- `chilli-core`: Contains the core logic, data structures, and configuration management for the application.
- `chilli-net`: Provides the networking components, including the TUN/TAP interface, DHCP server, and RADIUS client.
- `chilli-http`: Implements the UAM/captive portal HTTP server using the `axum` framework.
- `chilli-bin`: The main binary crate that integrates all the other components and runs the application.

## Building and Running

**Note:** This project is still in the early stages of development and is not yet functional.

To build the project, you will need to have Rust and Cargo installed. You can then build the project by running the following command from the root of the workspace:

```
cargo build
```

To run the application, you will need to create a `chilli.toml` configuration file. An example configuration file can be found in `chilli-core/tests/chilli.toml`. You can then run the application with the following command:

```
cargo run -p chilli-bin -- --config-file /path/to/your/chilli.toml
```

## Contributing

Contributions are welcome! Please feel free to open an issue or submit a pull request.
