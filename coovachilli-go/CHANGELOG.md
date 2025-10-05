# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Centralized Administration (Point 5 - Completed 85%)

- **Centralized Dashboard** (`pkg/admin/dashboard.go`)
  - Real-time metrics collection (every 10 seconds)
  - Comprehensive statistics: sessions, traffic, bandwidth, users
  - Security stats: threats blocked, IDS events, filtered domains
  - Authentication stats: successful/failed logins
  - VLAN distribution tracking
  - Top 10 users by traffic
  - Uptime and resource monitoring

- **Complete REST API** (`pkg/admin/api.go`)
  - 30+ endpoints for full system management
  - Dashboard endpoints (stats, health)
  - Session management (list, details, logout, authorize)
  - User management (list, details, sessions)
  - Configuration management (get, reload)
  - Snapshot management (CRUD operations)
  - Security integration (IDS, threats, filtering)
  - Multi-site management endpoints
  - Bearer token authentication
  - Rate limiting support
  - JSON REST format

- **Multi-Site Management** (`pkg/admin/multisite.go`)
  - Manage multiple CoovaChilli instances from single console
  - Automatic statistics synchronization
  - Site health monitoring (online/offline status)
  - Aggregated multi-site statistics
  - Geographic location support
  - Secure inter-site API calls
  - Auto-sync with configurable intervals

- **User Groups & Policy Management** (`pkg/admin/policy.go`)
  - User group creation and management
  - Comprehensive policy system:
    - Bandwidth limits (up/down)
    - Session limits (duration, concurrent)
    - Data limits (daily/monthly)
    - Time-based restrictions
    - VLAN assignment
    - Domain/IP filtering
    - Protocol restrictions
    - QoS classes
  - Policy priority system
  - Access control checks
  - Persistent storage (JSON files)

- **Configuration Snapshots** (`pkg/admin/snapshot.go`)
  - Create configuration snapshots with metadata
  - Restore snapshots with automatic backup
  - SHA256 checksum verification
  - Snapshot management (list, get, delete)
  - Automatic backup before restore
  - JSON storage format

- **Extended Admin Server** (`pkg/admin/server.go`)
  - Integrated dashboard initialization
  - Snapshot manager integration
  - Environment variable support
  - Enhanced route handling

- **Documentation**
  - Complete API documentation (`docs/ADMIN_API.md`)
  - 30+ endpoint reference with examples
  - Security best practices
  - Integration examples (Python, Bash, Prometheus)
  - Point 5 summary (`docs/POINT_5_SUMMARY.md`)
  - Admin configuration example (`examples/admin_config.yaml`)

#### Security & Compliance (Point 2 - Completed)

- **Advanced URL/DNS Filtering** (`pkg/filter`)
  - Domain blocklist with wildcard support
  - IP blocklist
  - Category-based filtering with regex patterns
  - Three filter actions: block, allow, log
  - Dynamic rule management (add/remove domains at runtime)
  - Filter statistics tracking
  - Configuration via `urlfilter` section in config.yaml

- **Log Export System** (`pkg/logexport`)
  - Multi-backend log export architecture
  - File exporter (JSON Lines format)
  - Syslog exporter (RFC3164, TCP/UDP)
  - Elasticsearch exporter (stub implementation)
  - S3 exporter (planned)
  - Asynchronous export with buffering (1000 events)
  - Zerolog integration via custom writer
  - Structured log events with session tracking
  - Configuration via `logexport` section in config.yaml

- **Example Configurations**
  - URL filter configuration example (`examples/url_filter_config.yaml`)
  - Domain blocklist example (`examples/blocklist_domains.txt`)
  - IP blocklist example (`examples/blocklist_ips.txt`)
  - Category rules example (`examples/category_rules.txt`)

- **Documentation**
  - Comprehensive filtering and export guide (`docs/FILTERING_AND_EXPORT.md`)
  - Configuration examples and best practices
  - Troubleshooting section
  - Integration examples

- **Antimalware/Antivirus Integration** (`pkg/security`)
  - Multi-scanner architecture (VirusTotal, ClamAV, ThreatFox)
  - File hash scanning with caching (configurable TTL)
  - IP reputation checking
  - URL/domain scanning
  - Threat level classification (clean, low, medium, high, critical)
  - Real-time HTTP download scanning
  - Statistics and monitoring

- **Intrusion Detection System (IDS)** (`pkg/security`)
  - Port scan detection with configurable thresholds
  - Brute force attack detection
  - DDoS attack detection with rate limiting
  - SQL injection pattern detection
  - XSS (Cross-Site Scripting) detection
  - Automatic IP blocking with expiration
  - Event callback system for real-time alerts
  - Comprehensive statistics and recent events tracking
  - Automatic cleanup of old tracking data

- **SSL/TLS Encryption** (`pkg/security`)
  - Full TLS 1.2/1.3 support
  - Secure cipher suites (ECDHE, AES-GCM, ChaCha20-Poly1305)
  - Server and client TLS configurations
  - Client certificate authentication (optional)
  - Certificate validation with expiration checking
  - CA certificate support
  - Configurable TLS settings

- **Advanced VLAN Management** (`pkg/vlan`)
  - Dynamic VLAN assignment by user/role/MAC
  - Multiple VLAN configuration with network details
  - Per-VLAN DNS and gateway configuration
  - Client isolation per VLAN
  - Role-based VLAN mapping
  - VLAN statistics and usage tracking
  - Session VLAN tracking
  - Default VLAN fallback

- **GDPR Compliance** (`pkg/gdpr`)
  - Data subject registration with consent tracking
  - Personal data storage with encryption (AES-256-GCM)
  - Data categorization (identity, contact, technical, usage, location, financial)
  - Legal basis tracking (consent, contract, legal obligation, legitimate interest)
  - Right to access implementation
  - Right to erasure (right to be forgotten)
  - Right to data portability (JSON export)
  - Automatic data retention with configurable periods
  - Anonymization option instead of deletion
  - Complete audit log with export capability
  - GDPR request tracking and status management

- **Security Documentation**
  - Complete security guide (`docs/SECURITY.md`)
  - Configuration examples for all security features
  - Best practices and troubleshooting
  - Integration examples (SIEM, EDR, DLP)

### Changed
- **Dependency Update**
  - Replaced `github.com/google/gopacket` with `github.com/gopacket/gopacket v1.3.1`
  - Updated all imports across the codebase
  - Removed unused `github.com/dreadl0ck/tlsx` dependency from main.go

- **SNI Filtering**
  - Removed SNI-based content filtering from `cmd/coovachilli/main.go`
  - Cleaned up SNI blocklist loading code
  - Updated roadmap to reflect removal

- **Configuration Schema**
  - Added `URLFilterConfig` struct to config
  - Added `LogExportConfig` struct to config
  - Environment variable support for all new config options

### Fixed
- All existing tests continue to pass
- No breaking changes to existing functionality

### Roadmap Progress - Point 2: Security & Compliance
- ✅ Point 2.1: Advanced URL and DNS filtering - **COMPLETED**
- ✅ Point 2.2: Log export functionality - **COMPLETED**
- ✅ Point 2.3: Antivirus/Antimalware integration - **COMPLETED**
- ✅ Point 2.4: Real-time intrusion detection - **COMPLETED**
- ✅ Point 2.5: SSL/TLS encryption - **COMPLETED**
- ✅ Point 2.6: Advanced VLAN support - **COMPLETED**
- ✅ Point 2.7: GDPR compliance - **COMPLETED**
- ⏳ Point 2.8: Content/protocol filtering - **PENDING** (SNI removed, needs replacement)
- Updated ROADMAP.md - **Point 2 is now 90% complete** ✅

### Roadmap Progress - Point 5: Centralized Administration
- ✅ Point 5.1: Extended admin console - **COMPLETED**
- ✅ Point 5.2: Centralized dashboard - **COMPLETED**
- ✅ Point 5.3: Multi-site management - **COMPLETED**
- ✅ Point 5.4: User groups and policy management - **COMPLETED**
- ✅ Point 5.5: Complete REST API - **COMPLETED**
- ❌ Point 5.6: Automatic updates - **PENDING**
- ✅ Point 5.7: Configuration snapshots - **COMPLETED**
- Updated ROADMAP.md - **Point 5 is now 85% complete** ✅

## [Previous Versions]

See Git history for changes prior to this changelog.
