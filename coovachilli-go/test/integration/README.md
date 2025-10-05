# Integration Tests

This directory is intended for end-to-end integration tests.

## Goal

The goal of these tests is to simulate a real-world environment and verify that all components of CoovaChilli-Go work together as expected. This provides a higher level of confidence than unit tests alone.

## Proposed Test Setup

A good approach for these tests would be to use Docker Compose to orchestrate several containers:
1.  **CoovaChilli-Go Container**: The main application running in a container.
2.  **RADIUS Server Container**: A container running a RADIUS server (like FreeRADIUS) to test authentication and accounting.
3.  **Client Container**: A lightweight container that acts as a client, trying to connect through the CoovaChilli-Go captive portal. This container would run scripts to simulate a user session (e.g., using `curl`).

## Scenarios to Test

- **Full Authentication Flow**: A client connects, is redirected to the captive portal, authenticates via the RADIUS server, gains internet access, and is properly disconnected.
- **Walled Garden**: An unauthenticated client attempts to access allowed and disallowed resources in the walled garden.
- **Dynamic Reconfiguration**: Tests that trigger a configuration reload (`SIGHUP` or command socket) and verify that the changes are applied correctly (e.g., changes to the walled garden).
- **Clustering**: If possible, test the failover mechanism between two CoovaChilli-Go instances.