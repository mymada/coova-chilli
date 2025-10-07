# RADIUS Advanced Features Implementation

This document describes the advanced RADIUS and bandwidth shaping features implemented in CoovaChilli-Go.

## Table of Contents

1. [EAP Support](#eap-support)
2. [RADIUS Proxy](#radius-proxy)
3. [Advanced Bandwidth Shaping](#advanced-bandwidth-shaping)
4. [QoS & Traffic Prioritization](#qos--traffic-prioritization)
5. [Configuration](#configuration)
6. [Usage Examples](#usage-examples)

## EAP Support

### Overview

Full support for Enterprise-grade EAP authentication methods:

- **EAP-TLS**: Certificate-based authentication using TLS
- **EAP-TTLS**: Tunneled TLS with flexible inner authentication
- **PEAP**: Protected EAP with MSCHAPv2 support

### Features

- Complete EAP state machine implementation
- TLS handshake management with fragmentation support
- PMK (Pairwise Master Key) extraction and derivation
- MS-MPPE key encryption/decryption
- Support for EAP re-authentication
- Session resumption support

### Implementation Files

- `pkg/radius/eap.go`: Core EAP implementation
- `pkg/radius/eap_test.go`: Comprehensive test suite

### Key Functions

```go
// Handle EAP authentication request
func (c *Client) HandleEAPRequest(session *core.Session, eapData []byte) (*radius.Packet, error)

// Send EAP Access-Request to RADIUS server
func (c *Client) SendEAPAccessRequest(session *core.Session, eapPayload []byte, state []byte) (*radius.Packet, []byte, error)

// Extract encryption keys from RADIUS response
func (c *Client) extractEAPKeys(eapSession *EAPSession, radiusResp *radius.Packet, authenticator []byte) error
```

### Configuration

```yaml
# Enable EAP authentication
eapenable: true
eapmethod: PEAP  # Options: TLS, TTLS, PEAP

# Certificate configuration
eapcertfile: /etc/coovachilli/certs/eap-server.pem
eapkeyfile: /etc/coovachilli/certs/eap-server-key.pem
eapcafile: /etc/coovachilli/certs/eap-ca.pem
```

## RADIUS Proxy

### Overview

Advanced RADIUS proxy with intelligent realm-based routing, load balancing, and automatic failover.

### Features

- **Realm-based routing**: Route requests based on username realm (@domain or DOMAIN\)
- **Multiple load balancing strategies**:
  - Round-robin: Distribute load evenly across servers
  - Failover: Use highest priority active server
  - Least-load: Select server with fewest failures
- **Health monitoring**: Automatic health checks with configurable intervals
- **Automatic failover**: Inactive servers are bypassed
- **Retry logic**: Configurable retry attempts per server
- **Request forwarding**: Transparent proxy with attribute preservation

### Implementation Files

- `pkg/radius/proxy.go`: Enhanced proxy implementation
- `pkg/radius/proxy_test.go`: Comprehensive test suite

### Key Structures

```go
type ProxyRealm struct {
    Name           string
    Servers        []ProxyUpstreamServer
    LoadBalancing  string // "round-robin", "failover", "least-load"
    currentIndex   int
}

type ProxyUpstreamServer struct {
    Address    string
    AuthPort   int
    AcctPort   int
    Secret     []byte
    Timeout    time.Duration
    MaxRetries int
    Priority   int
    Weight     int
    Active     bool
}
```

### Configuration

```yaml
# Enable RADIUS proxy
proxyenable: true
proxylisten: 0.0.0.0
proxyport: 1645
proxysecret: proxysecret123
```

### Usage Example

```go
// Create proxy server
proxy := NewProxyServer(cfg, sessionManager, radiusClient, logger)

// Configure realm routing
proxy.AddRealm(&ProxyRealm{
    Name:          "example.com",
    LoadBalancing: "round-robin",
    Servers: []ProxyUpstreamServer{
        {
            Address:    "radius1.example.com",
            AuthPort:   1812,
            AcctPort:   1813,
            Secret:     []byte("secret1"),
            Timeout:    5 * time.Second,
            MaxRetries: 3,
            Active:     true,
        },
        {
            Address:    "radius2.example.com",
            AuthPort:   1812,
            AcctPort:   1813,
            Secret:     []byte("secret2"),
            Priority:   2,
            Active:     true,
        },
    },
})

// Start proxy server
go proxy.Start()

// Start health checks (every 30 seconds)
go proxy.StartHealthCheck(30 * time.Second)
```

## Advanced Bandwidth Shaping

### Overview

Granular per-user bandwidth control with token bucket algorithm and burst support.

### Features

- **Per-session bandwidth limits**: Upload and download limits per user
- **Token bucket algorithm**: Smooth traffic shaping with burst allowance
- **Dynamic adjustment**: Modify limits on-the-fly via RADIUS or API
- **Configurable bucket sizes**: Control burst behavior
- **Statistics tracking**: Monitor shaped traffic and drops
- **Minimum guarantees**: Ensure baseline bandwidth per user

### Implementation Files

- `pkg/core/shaper.go`: Enhanced shaper with QoS support
- `pkg/core/shaper_test.go`: Test suite

### Key Functions

```go
// Initialize bandwidth shaper for a session
func (s *Session) InitializeShaper(cfg *config.Config)

// Check if packet should be dropped based on limits
func (s *Session) ShouldDropPacket(packetSize uint64, isUpload bool) bool

// Dynamically adjust bandwidth limits
func (s *Session) AdjustBandwidthLimits(uploadBps, downloadBps uint64)

// Update shaping statistics
func (s *Session) UpdateShaperStats(packetSize uint64, isUpload bool)

// Reset buckets (for burst traffic)
func (s *Session) ResetBandwidthBuckets()
```

### Configuration

```yaml
# Default bandwidth limits (in bits per second)
defbandwidthmaxdown: 1000000  # 1 Mbps download
defbandwidthmaxup: 512000     # 512 Kbps upload

# Bucket configuration (in bytes)
bwbucketupsize: 65536    # 64 KB upload burst
bwbucketdnsize: 131072   # 128 KB download burst
bwbucketminsize: 4096    # 4 KB minimum
```

### RADIUS Attributes

Bandwidth limits can be set via RADIUS attributes:

- `Filter-Id`: Custom bandwidth policy
- `Ascend-Data-Rate`: Upload rate
- `Ascend-Xmit-Rate`: Download rate

## QoS & Traffic Prioritization

### Overview

Quality of Service with traffic classification and priority-based shaping.

### Features

- **Traffic classes**: 6 predefined QoS classes
- **Priority levels**: Higher priority traffic gets preferential treatment
- **Guaranteed bandwidth**: Minimum rate guarantees per class
- **Probabilistic dropping**: RED-like algorithm for congestion management
- **Burst allowance**: Class-specific burst sizes
- **Custom policies**: Define per-session traffic classes

### QoS Classes

1. **Critical** (Priority 6): Mission-critical traffic
   - Guaranteed: 256 Kbps
   - Max: 1 Mbps
   - Drop probability: 0.01%

2. **Voice** (Priority 5): VoIP traffic
   - Guaranteed: 64 Kbps
   - Max: 128 Kbps
   - Drop probability: 0.1%

3. **Video** (Priority 4): Video streaming
   - Guaranteed: 512 Kbps
   - Max: 2 Mbps
   - Drop probability: 1%

4. **Interactive** (Priority 3): Gaming, SSH, etc.
   - Guaranteed: 128 Kbps
   - Max: 512 Kbps
   - Drop probability: 5%

5. **Best Effort** (Priority 2): Standard traffic
   - Guaranteed: None
   - Max: 1 Mbps
   - Drop probability: 10%

6. **Background** (Priority 1): Downloads, updates
   - Guaranteed: None
   - Max: 256 Kbps
   - Drop probability: 20%

### Key Structures

```go
type TrafficClass struct {
    Name            string
    Priority        int
    GuaranteedRate  uint64  // bits per second
    MaxRate         uint64  // bits per second
    BurstSize       uint64  // bytes
    DropProbability float64
}

type ShaperStats struct {
    BytesSent       uint64
    BytesReceived   uint64
    PacketsDropped  uint64
    PacketsShaped   uint64
    AvgUploadRate   float64
    AvgDownloadRate float64
}
```

### Key Functions

```go
// Apply QoS policy to packet
func (s *Session) ApplyQoS(packetSize uint64, qosClass QoSClass, isUpload bool) bool

// Set custom traffic class
func (s *Session) SetTrafficClass(qosClass QoSClass, tc TrafficClass)

// Get traffic class configuration
func (s *Session) GetTrafficClass(qosClass QoSClass) *TrafficClass

// Get shaping statistics
func (s *Session) GetShaperStats() ShaperStats
```

### Usage Example

```go
// Apply QoS to a packet
shouldDrop := session.ApplyQoS(1500, core.QoSClassVoice, true)
if shouldDrop {
    session.RecordDroppedPacket()
    return
}

// Set custom traffic class for premium users
session.SetTrafficClass(core.QoSClassVideo, core.TrafficClass{
    Name:            "Premium Video",
    Priority:        5,
    GuaranteedRate:  2000000,  // 2 Mbps
    MaxRate:         10000000, // 10 Mbps
    BurstSize:       262144,   // 256 KB
    DropProbability: 0.001,
})

// Monitor shaping statistics
stats := session.GetShaperStats()
fmt.Printf("Avg upload: %.2f Kbps\n", stats.AvgUploadRate*8/1000)
fmt.Printf("Packets dropped: %d\n", stats.PacketsDropped)
```

## Configuration

### Complete Example

See `config.example.yaml` for a complete configuration with all features enabled.

### Key Settings

```yaml
# RADIUS
radiusserver1: 192.168.1.10
radiusserver2: 192.168.1.11
radiustimeout: 3s

# RadSec (RADIUS over TLS)
radsecenable: false
radsecport: 2083
radseccertfile: /etc/coovachilli/certs/client.pem
radseckeyfile: /etc/coovachilli/certs/client-key.pem

# RADIUS Proxy
proxyenable: false
proxylisten: 0.0.0.0
proxyport: 1645

# EAP
eapenable: false
eapmethod: PEAP
eapcertfile: /etc/coovachilli/certs/eap-server.pem

# Bandwidth Shaping
defbandwidthmaxdown: 1000000
defbandwidthmaxup: 512000
bwbucketupsize: 65536
bwbucketdnsize: 131072
```

## Usage Examples

### Example 1: EAP-PEAP Authentication

```go
// Client initiates EAP authentication
eapData := []byte{0x02, 0x01, 0x00, 0x0d, 0x01, ...} // EAP packet

// Handle EAP request
response, err := radiusClient.HandleEAPRequest(session, eapData)
if err != nil {
    log.Error("EAP authentication failed", err)
    return
}

// Process RADIUS response
if response.Code == radius.CodeAccessAccept {
    session.Authenticated = true
    log.Info("EAP authentication successful")
}
```

### Example 2: RADIUS Proxy with Realms

```go
// Configure proxy with multiple realms
proxy := NewProxyServer(cfg, sm, rc, logger)

// Corporate realm - high priority servers
proxy.AddRealm(&ProxyRealm{
    Name:          "corp.example.com",
    LoadBalancing: "failover",
    Servers: []ProxyUpstreamServer{
        {Address: "radius-corp-1.local", AuthPort: 1812, Priority: 10, Active: true},
        {Address: "radius-corp-2.local", AuthPort: 1812, Priority: 5, Active: true},
    },
})

// Guest realm - round-robin load balancing
proxy.AddRealm(&ProxyRealm{
    Name:          "guest.example.com",
    LoadBalancing: "round-robin",
    Servers: []ProxyUpstreamServer{
        {Address: "radius-guest-1.local", AuthPort: 1812, Active: true},
        {Address: "radius-guest-2.local", AuthPort: 1812, Active: true},
        {Address: "radius-guest-3.local", AuthPort: 1812, Active: true},
    },
})

proxy.Start()
proxy.StartHealthCheck(30 * time.Second)
```

### Example 3: Dynamic Bandwidth Adjustment

```go
// User upgrades to premium plan
if userUpgraded {
    // Adjust bandwidth to premium limits
    session.AdjustBandwidthLimits(
        10000000, // 10 Mbps upload
        50000000, // 50 Mbps download
    )

    // Apply premium QoS class
    session.SetTrafficClass(core.QoSClassVideo, core.TrafficClass{
        Name:            "Premium",
        Priority:        6,
        GuaranteedRate:  5000000,
        MaxRate:         50000000,
        BurstSize:       524288,
        DropProbability: 0.0001,
    })
}

// Monitor usage
stats := session.GetShaperStats()
if stats.AvgDownloadRate > threshold {
    log.Warn("User exceeding average rate",
        "rate", stats.AvgDownloadRate)
}
```

### Example 4: QoS-based Traffic Shaping

```go
// Classify packet based on port/protocol
var qosClass core.QoSClass

switch {
case isVoIPPacket(packet):
    qosClass = core.QoSClassVoice
case isVideoStreamingPacket(packet):
    qosClass = core.QoSClassVideo
case isGamingPacket(packet):
    qosClass = core.QoSClassInteractive
default:
    qosClass = core.QoSClassBestEffort
}

// Apply QoS policy
shouldDrop := session.ApplyQoS(
    uint64(len(packet.Data)),
    qosClass,
    packet.Direction == DirectionUpload,
)

if shouldDrop {
    session.RecordDroppedPacket()
    metrics.RecordDrop(qosClass)
    return nil // Drop packet
}

session.RecordShapedPacket()
return packet // Forward packet
```

## Testing

### Run Tests

```bash
# Run all tests
go test ./pkg/radius/... -v

# Run with coverage
go test ./pkg/radius/... -cover

# Run benchmarks
go test ./pkg/radius/... -bench=. -benchmem

# Run specific test
go test ./pkg/radius -run TestEAPPacketParse -v
```

### Test Coverage

- EAP packet parsing and encoding
- RADIUS proxy realm routing
- Load balancing algorithms
- Bandwidth shaper token bucket
- QoS traffic classification
- Health monitoring
- Failover scenarios

## Performance Considerations

### EAP Performance

- TLS handshake caching reduces CPU overhead
- Fragmentation support for large certificates
- Efficient PMK derivation

### Proxy Performance

- Concurrent request handling
- Connection pooling for upstream servers
- Efficient realm lookup with hash maps
- Lock-free health check reads

### Shaper Performance

- O(1) packet decision time
- Lock-per-session granularity
- Efficient token bucket algorithm
- Minimal memory overhead per session

## Migration from C Version

### Key Differences

1. **EAP Support**: Go version has full EAP-TLS/TTLS/PEAP support (C version limited)
2. **Proxy**: Enhanced with realm routing and multiple load balancing strategies
3. **Shaping**: Added QoS classes with priority-based treatment
4. **Type Safety**: Compile-time type checking vs. C preprocessor macros
5. **Concurrency**: Go's goroutines for better concurrent request handling

### Compatibility

- RADIUS attributes remain compatible
- Configuration format extended but backward compatible
- Session state can be migrated

## Future Enhancements

Possible future improvements:

1. **EAP Fast Reconnect**: Reduce re-authentication time
2. **Dynamic QoS Policies**: Policy updates via RADIUS CoA
3. **Advanced Shaping**: HTB/CBQ integration for kernel-level shaping
4. **Proxy Clustering**: Distributed proxy with state sharing
5. **ML-based QoS**: Automatic traffic classification using ML

## References

- [RFC 2865](https://tools.ietf.org/html/rfc2865): RADIUS
- [RFC 3748](https://tools.ietf.org/html/rfc3748): EAP
- [RFC 5216](https://tools.ietf.org/html/rfc5216): EAP-TLS
- [RFC 5281](https://tools.ietf.org/html/rfc5281): EAP-TTLS
- [RFC 2548](https://tools.ietf.org/html/rfc2548): Microsoft RADIUS attributes
- [RFC 2697](https://tools.ietf.org/html/rfc2697): Single Rate Three Color Marker
- [RFC 2698](https://tools.ietf.org/html/rfc2698): Two Rate Three Color Marker

## Support

For issues or questions:
- GitHub Issues: https://github.com/yourusername/coovachilli-go/issues
- Documentation: https://docs.coovachilli-go.org
- Community Forum: https://forum.coovachilli-go.org
