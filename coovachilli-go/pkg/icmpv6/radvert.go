package icmpv6

import (
	"encoding/binary"
	"fmt"
	"net"

	"coovachilli-go/pkg/config"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BuildRouterAdvertisement creates a Router Advertisement packet compatible with older gopacket APIs.
func BuildRouterAdvertisement(cfg *config.Config, soliciterIP net.IP) ([]byte, error) {
	// A fixed MAC address for the router's TUN interface for simplicity.
	routerMAC, _ := net.ParseMAC("02:00:00:ca:fe:01")

	// Generate the router's link-local address from its MAC address using EUI-64 format.
	routerLinkLocalIP := make(net.IP, 16)
	routerLinkLocalIP[0] = 0xfe
	routerLinkLocalIP[1] = 0x80
	routerLinkLocalIP[8] = routerMAC[0] ^ 0x02 // Invert the U/L bit
	routerLinkLocalIP[9] = routerMAC[1]
	routerLinkLocalIP[10] = routerMAC[2]
	routerLinkLocalIP[11] = 0xff
	routerLinkLocalIP[12] = 0xfe
	routerLinkLocalIP[13] = routerMAC[3]
	routerLinkLocalIP[14] = routerMAC[4]
	routerLinkLocalIP[15] = routerMAC[5]

	// Construct the IPv6 layer of the packet.
	ipv6 := &layers.IPv6{
		Version:    6,
		SrcIP:      routerLinkLocalIP,
		DstIP:      soliciterIP,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255, // As per RFC 4861, RAs must be sent with a hop limit of 255.
	}

	// Manually construct the ICMPv6 Router Advertisement layer payload.
	// The layers.ICMPv6 struct in older gopacket versions is minimal.
	// We build the header and options as a raw byte slice.
	icmpv6Payload := make([]byte, 16) // RA header is 16 bytes
	icmpv6Payload[0] = 134 // Type: Router Advertisement
	icmpv6Payload[1] = 0   // Code
	// Checksum (bytes 2-3) will be calculated by gopacket
	icmpv6Payload[4] = 64  // Hop Limit
	// Flags (M=0, O=0), bytes 5
	binary.BigEndian.PutUint16(icmpv6Payload[6:8], 1800) // Router Lifetime

	// Option: Source Link-Layer Address (Type 1)
	optSrcLLAddr := make([]byte, 8)
	optSrcLLAddr[0] = 1  // Option Type
	optSrcLLAddr[1] = 1  // Length in units of 8 octets (1*8=8)
	copy(optSrcLLAddr[2:], routerMAC)
	icmpv6Payload = append(icmpv6Payload, optSrcLLAddr...)

	// Option: Prefix Information (Type 3)
	if cfg.NetV6.IP != nil {
		prefixLen, _ := cfg.NetV6.Mask.Size()
		optPrefixInfo := make([]byte, 32)
		optPrefixInfo[0] = 3    // Option Type
		optPrefixInfo[1] = 4    // Length in units of 8 octets (4*8=32)
		optPrefixInfo[2] = byte(prefixLen)
		optPrefixInfo[3] = 0xc0 // Flags: On-Link (L=1), Autonomous (A=1)
		binary.BigEndian.PutUint32(optPrefixInfo[4:8], 2592000) // Valid Lifetime: 30 days
		binary.BigEndian.PutUint32(optPrefixInfo[8:12], 604800) // Preferred Lifetime: 7 days
		// Bytes 12-15 are reserved
		copy(optPrefixInfo[16:], cfg.NetV6.IP.To16())
		icmpv6Payload = append(icmpv6Payload, optPrefixInfo...)
	}

	// Use a simple ICMPv6 struct and attach the manually created payload.
	icmpv6 := &layers.ICMPv6{}
	icmpv6.TypeCode = layers.ICMPv6TypeCode(binary.BigEndian.Uint16(icmpv6Payload[0:2]))
	icmpv6.Payload = icmpv6Payload[4:] // The rest of the payload after Type and Code

	// The checksum is calculated over the ICMPv6 layer and a pseudo-header from the IPv6 layer.
	icmpv6.SetNetworkLayerForChecksum(ipv6)

	// Serialize the complete packet into a byte slice.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true, // Automatically calculate the ICMPv6 checksum.
		FixLengths:       true, // Automatically calculate content lengths.
	}

	// Manually create the ICMPv6 layer for serialization since the struct is minimal
	// This involves creating a custom layer that just holds our raw payload.
	customICMPv6Layer := &gopacket.Payload{
		Data: icmpv6Payload,
	}

	// We need to manually calculate the checksum here for the custom payload
	ipv6.Length = uint16(len(icmpv6Payload))
	csum, err := ipv6.ComputeChecksum(icmpv6Payload, layers.IPProtocolICMPv6)
	if err != nil {
		return nil, fmt.Errorf("failed to compute checksum: %w", err)
	}
	binary.BigEndian.PutUint16(icmpv6Payload[2:4], csum)


	if err := gopacket.SerializeLayers(buf, opts, ipv6, gopacket.Payload(icmpv6Payload)); err != nil {
		return nil, fmt.Errorf("failed to serialize RA packet: %w", err)
	}

	return buf.Bytes(), nil
}