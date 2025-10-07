package security

import (
	"net"
)

// ValidateIPv6Address performs security validation on IPv6 addresses
func ValidateIPv6Address(ip net.IP) bool {
	if ip == nil || ip.To4() != nil {
		return false // Not an IPv6 address
	}

	// Reject unspecified address (::)
	if ip.IsUnspecified() {
		return false
	}

	// Reject loopback (::1)
	if ip.IsLoopback() {
		return false
	}

	// Reject multicast addresses for source IPs (ff00::/8)
	if ip.IsMulticast() {
		return false
	}

	// ✅ SECURITY: Reject IPv4-mapped IPv6 addresses (::ffff:0:0/96)
	// These can be used for IPv4/IPv6 confusion attacks
	if len(ip) == 16 &&
		ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
		ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
		ip[8] == 0 && ip[9] == 0 && ip[10] == 0xff && ip[11] == 0xff {
		return false
	}

	// ✅ SECURITY: Reject IPv4-compatible IPv6 addresses (::/96)
	// Deprecated and can cause security issues
	if len(ip) == 16 &&
		ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0 &&
		ip[4] == 0 && ip[5] == 0 && ip[6] == 0 && ip[7] == 0 &&
		ip[8] == 0 && ip[9] == 0 && ip[10] == 0 && ip[11] == 0 &&
		!(ip[12] == 0 && ip[13] == 0 && ip[14] == 0 && ip[15] == 0) {
		return false
	}

	// ✅ SECURITY: Reject documentation prefix (2001:db8::/32)
	if len(ip) >= 4 && ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8 {
		return false
	}

	// ✅ SECURITY: Reject 6to4 (2002::/16) - deprecated
	if len(ip) >= 2 && ip[0] == 0x20 && ip[1] == 0x02 {
		return false
	}

	// ✅ SECURITY: Reject Teredo (2001::/32) - can be used for tunneling attacks
	if len(ip) >= 4 && ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x00 && ip[3] == 0x00 {
		return false
	}

	return true
}

// IsLinkLocal checks if an IPv6 address is link-local (fe80::/10)
func IsLinkLocal(ip net.IP) bool {
	if ip == nil || ip.To4() != nil {
		return false
	}
	return len(ip) >= 2 && ip[0] == 0xfe && (ip[1]&0xc0) == 0x80
}

// IsUniqueLocal checks if an IPv6 address is unique local (fc00::/7)
func IsUniqueLocal(ip net.IP) bool {
	if ip == nil || ip.To4() != nil {
		return false
	}
	return len(ip) >= 1 && (ip[0]&0xfe) == 0xfc
}

// IsGlobalUnicast checks if an IPv6 address is global unicast
func IsGlobalUnicast(ip net.IP) bool {
	if ip == nil || ip.To4() != nil {
		return false
	}
	// Global unicast: 2000::/3
	return len(ip) >= 1 && (ip[0]&0xe0) == 0x20
}

// ValidateIPv6Packet performs comprehensive security checks on an IPv6 packet
func ValidateIPv6Packet(srcIP, dstIP net.IP) error {
	// Source address validation
	if !ValidateIPv6Address(srcIP) {
		return &SecurityError{
			Type:    "InvalidSourceIPv6",
			Message: "Source IPv6 address failed validation",
			Details: map[string]interface{}{"src_ip": srcIP.String()},
		}
	}

	// ✅ SECURITY: Source cannot be multicast
	if srcIP.IsMulticast() {
		return &SecurityError{
			Type:    "MulticastSourceIPv6",
			Message: "IPv6 source address cannot be multicast",
			Details: map[string]interface{}{"src_ip": srcIP.String()},
		}
	}

	// Destination address validation (less strict)
	if dstIP.IsUnspecified() {
		return &SecurityError{
			Type:    "UnspecifiedDestIPv6",
			Message: "IPv6 destination address cannot be unspecified",
			Details: map[string]interface{}{"dst_ip": dstIP.String()},
		}
	}

	return nil
}

// SecurityError represents an IPv6 security violation
type SecurityError struct {
	Type    string
	Message string
	Details map[string]interface{}
}

func (e *SecurityError) Error() string {
	return e.Message
}

// ValidateDHCPv6Request validates security aspects of a DHCPv6 request
func ValidateDHCPv6Request(srcIP net.IP) error {
	// DHCPv6 requests should come from link-local addresses
	if !IsLinkLocal(srcIP) && !srcIP.IsUnspecified() {
		return &SecurityError{
			Type:    "InvalidDHCPv6Source",
			Message: "DHCPv6 requests must come from link-local or unspecified addresses",
			Details: map[string]interface{}{"src_ip": srcIP.String()},
		}
	}

	return nil
}

// ValidateICMPv6Source validates the source address for ICMPv6 packets
func ValidateICMPv6Source(srcIP net.IP, icmpType uint8) error {
	// For NDP packets (NS, NA, RS, RA), source must be link-local or unspecified
	if icmpType >= 133 && icmpType <= 137 { // Router/Neighbor Solicitation/Advertisement
		if !IsLinkLocal(srcIP) && !srcIP.IsUnspecified() {
			return &SecurityError{
				Type:    "InvalidNDPSource",
				Message: "NDP packets must originate from link-local addresses",
				Details: map[string]interface{}{
					"src_ip":    srcIP.String(),
					"icmp_type": icmpType,
				},
			}
		}
	}

	return nil
}
