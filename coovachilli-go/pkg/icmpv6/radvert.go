package icmpv6

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"coovachilli-go/pkg/config"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// BuildRouterAdvertisement creates a Router Advertisement packet using the modern gopacket API.
func BuildRouterAdvertisement(cfg *config.Config, soliciterIP net.IP) ([]byte, error) {
	routerMAC, _ := net.ParseMAC("02:00:00:ca:fe:01")

	routerLinkLocalIP := make(net.IP, 16)
	routerLinkLocalIP[0] = 0xfe
	routerLinkLocalIP[1] = 0x80
	routerLinkLocalIP[8] = routerMAC[0] ^ 0x02
	routerLinkLocalIP[9] = routerMAC[1]
	routerLinkLocalIP[10] = routerMAC[2]
	routerLinkLocalIP[11] = 0xff
	routerLinkLocalIP[12] = 0xfe
	routerLinkLocalIP[13] = routerMAC[3]
	routerLinkLocalIP[14] = routerMAC[4]
	routerLinkLocalIP[15] = routerMAC[5]

	ipv6 := &layers.IPv6{
		Version:    6,
		SrcIP:      routerLinkLocalIP,
		DstIP:      soliciterIP,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   255,
	}

	icmpv6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRouterAdvertisement, 0),
	}
	icmpv6.SetNetworkLayerForChecksum(ipv6)

	ra := &layers.ICMPv6RouterAdvertisement{
		HopLimit:       64,
		RouterLifetime: 1800,
	}

	optSrcLLAddr := layers.ICMPv6Option{
		Type: layers.ICMPv6OptionSourceLinkLayerAddress,
		Data: routerMAC,
	}

	prefixLen, _ := cfg.NetV6.Mask.Size()
	optPrefixInfoData := make([]byte, 30)
	optPrefixInfoData[0] = byte(prefixLen)
	optPrefixInfoData[1] = 0xc0
	binary.BigEndian.PutUint32(optPrefixInfoData[4:8], uint32((2592000 * time.Second).Seconds()))
	binary.BigEndian.PutUint32(optPrefixInfoData[8:12], uint32((604800 * time.Second).Seconds()))
	copy(optPrefixInfoData[16:], cfg.NetV6.IP.To16())

	optPrefixInfo := layers.ICMPv6Option{
		Type: layers.ICMPv6OptionPrefixInfo,
		Data: optPrefixInfoData,
	}

	ra.Options = append(ra.Options, optSrcLLAddr, optPrefixInfo)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, ipv6, icmpv6, ra); err != nil {
		return nil, fmt.Errorf("failed to serialize RA packet: %w", err)
	}

	return buf.Bytes(), nil
}