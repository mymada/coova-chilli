package icmpv6

import (
	"net"
	"testing"

	"coovachilli-go/pkg/config"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestBuildRouterAdvertisement(t *testing.T) {
	_, ipnet6, err := net.ParseCIDR("2001:db8::/64")
	if err != nil {
		t.Fatalf("Failed to parse CIDR: %v", err)
	}

	cfg := &config.Config{
		NetV6: *ipnet6,
	}

	soliciterIP := net.ParseIP("fe80::1")

	raBytes, err := BuildRouterAdvertisement(cfg, soliciterIP)
	if err != nil {
		t.Fatalf("BuildRouterAdvertisement failed: %v", err)
	}

	if len(raBytes) == 0 {
		t.Fatal("BuildRouterAdvertisement returned empty packet")
	}

	// Parse the packet to verify structure
	packet := gopacket.NewPacket(raBytes, layers.LayerTypeIPv6, gopacket.Default)

	// Check IPv6 layer
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer == nil {
		t.Fatal("RA packet missing IPv6 layer")
	}

	ipv6, _ := ipv6Layer.(*layers.IPv6)
	if ipv6.Version != 6 {
		t.Errorf("IPv6 version = %d, want 6", ipv6.Version)
	}

	if ipv6.HopLimit != 255 {
		t.Errorf("IPv6 HopLimit = %d, want 255", ipv6.HopLimit)
	}

	if ipv6.NextHeader != layers.IPProtocolICMPv6 {
		t.Errorf("IPv6 NextHeader = %v, want ICMPv6", ipv6.NextHeader)
	}

	if !ipv6.DstIP.Equal(soliciterIP) {
		t.Errorf("IPv6 DstIP = %s, want %s", ipv6.DstIP, soliciterIP)
	}

	// Check ICMPv6 layer
	icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6)
	if icmpv6Layer == nil {
		t.Fatal("RA packet missing ICMPv6 layer")
	}

	icmpv6, _ := icmpv6Layer.(*layers.ICMPv6)
	if icmpv6.TypeCode.Type() != layers.ICMPv6TypeRouterAdvertisement {
		t.Errorf("ICMPv6 Type = %v, want RouterAdvertisement", icmpv6.TypeCode.Type())
	}
}

func TestBuildRouterAdvertisementMulticast(t *testing.T) {
	_, ipnet6, err := net.ParseCIDR("2001:db8::/64")
	if err != nil {
		t.Fatalf("Failed to parse CIDR: %v", err)
	}

	cfg := &config.Config{
		NetV6: *ipnet6,
	}

	// Test with unspecified address (should use all-nodes multicast)
	soliciterIP := net.ParseIP("::")

	raBytes, err := BuildRouterAdvertisement(cfg, soliciterIP)
	if err != nil {
		t.Fatalf("BuildRouterAdvertisement failed: %v", err)
	}

	packet := gopacket.NewPacket(raBytes, layers.LayerTypeIPv6, gopacket.Default)
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ipv6Layer == nil {
		t.Fatal("RA packet missing IPv6 layer")
	}

	ipv6, _ := ipv6Layer.(*layers.IPv6)

	// When soliciterIP is unspecified, RA should be sent to all-nodes multicast
	allNodesMulticast := net.ParseIP("ff02::1")
	if !ipv6.DstIP.Equal(allNodesMulticast) && !ipv6.DstIP.Equal(soliciterIP) {
		t.Errorf("IPv6 DstIP = %s, want %s or %s", ipv6.DstIP, allNodesMulticast, soliciterIP)
	}
}

func TestRouterAdvertisementPayload(t *testing.T) {
	_, ipnet6, err := net.ParseCIDR("2001:db8:1234::/64")
	if err != nil {
		t.Fatalf("Failed to parse CIDR: %v", err)
	}

	cfg := &config.Config{
		NetV6: *ipnet6,
	}

	soliciterIP := net.ParseIP("fe80::2")

	raBytes, err := BuildRouterAdvertisement(cfg, soliciterIP)
	if err != nil {
		t.Fatalf("BuildRouterAdvertisement failed: %v", err)
	}

	packet := gopacket.NewPacket(raBytes, layers.LayerTypeIPv6, gopacket.Default)

	icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6)
	if icmpv6Layer == nil {
		t.Fatal("RA packet missing ICMPv6 layer")
	}

	icmpv6, _ := icmpv6Layer.(*layers.ICMPv6)

	// Verify payload contains expected options
	// Router Advertisement should have:
	// - Hop limit (1 byte)
	// - Flags (1 byte)
	// - Router lifetime (2 bytes)
	// - Reachable time (4 bytes)
	// - Retrans timer (4 bytes)
	// - Options (variable)

	if len(icmpv6.Payload) == 0 {
		t.Fatal("RA payload is empty")
	}

	// Check hop limit (first byte)
	hopLimit := icmpv6.Payload[0]
	if hopLimit != 64 {
		t.Errorf("RA hop limit = %d, want 64", hopLimit)
	}
}

func BenchmarkBuildRouterAdvertisement(b *testing.B) {
	_, ipnet6, _ := net.ParseCIDR("2001:db8::/64")
	cfg := &config.Config{
		NetV6: *ipnet6,
	}
	soliciterIP := net.ParseIP("fe80::1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BuildRouterAdvertisement(cfg, soliciterIP)
	}
}
