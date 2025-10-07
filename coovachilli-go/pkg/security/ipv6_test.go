package security

import (
	"net"
	"testing"
)

func TestValidateIPv6Address(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "Valid global unicast",
			ip:       "2001:db9::1",
			expected: true,
		},
		{
			name:     "Valid link-local",
			ip:       "fe80::1",
			expected: true,
		},
		{
			name:     "Unspecified address",
			ip:       "::",
			expected: false,
		},
		{
			name:     "Loopback address",
			ip:       "::1",
			expected: false,
		},
		{
			name:     "Multicast address",
			ip:       "ff02::1",
			expected: false,
		},
		{
			name:     "IPv4-mapped IPv6",
			ip:       "::ffff:192.0.2.1",
			expected: false,
		},
		{
			name:     "Documentation prefix",
			ip:       "2001:db8::1",
			expected: false,
		},
		{
			name:     "6to4 address",
			ip:       "2002:c000:0201::1",
			expected: false,
		},
		{
			name:     "Teredo address",
			ip:       "2001:0:4136:e378:8000:63bf:3fff:fdd2",
			expected: false,
		},
		{
			name:     "IPv4 address",
			ip:       "192.0.2.1",
			expected: false,
		},
		{
			name:     "Unique local address",
			ip:       "fd00::1",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := ValidateIPv6Address(ip)
			if result != tt.expected {
				t.Errorf("ValidateIPv6Address(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsLinkLocal(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "Link-local address",
			ip:       "fe80::1",
			expected: true,
		},
		{
			name:     "Link-local with interface",
			ip:       "fe80::a00:27ff:fe4e:66a1",
			expected: true,
		},
		{
			name:     "Global unicast",
			ip:       "2001:db9::1",
			expected: false,
		},
		{
			name:     "Unique local",
			ip:       "fd00::1",
			expected: false,
		},
		{
			name:     "IPv4 address",
			ip:       "192.168.1.1",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := IsLinkLocal(ip)
			if result != tt.expected {
				t.Errorf("IsLinkLocal(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsUniqueLocal(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "Unique local fc00",
			ip:       "fc00::1",
			expected: true,
		},
		{
			name:     "Unique local fd00",
			ip:       "fd00::1",
			expected: true,
		},
		{
			name:     "Global unicast",
			ip:       "2001:db9::1",
			expected: false,
		},
		{
			name:     "Link-local",
			ip:       "fe80::1",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := IsUniqueLocal(ip)
			if result != tt.expected {
				t.Errorf("IsUniqueLocal(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsGlobalUnicast(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{
			name:     "Global unicast 2001",
			ip:       "2001:db9::1",
			expected: true,
		},
		{
			name:     "Global unicast 2400",
			ip:       "2400::1",
			expected: true,
		},
		{
			name:     "Link-local",
			ip:       "fe80::1",
			expected: false,
		},
		{
			name:     "Unique local",
			ip:       "fd00::1",
			expected: false,
		},
		{
			name:     "Multicast",
			ip:       "ff02::1",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			result := IsGlobalUnicast(ip)
			if result != tt.expected {
				t.Errorf("IsGlobalUnicast(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestValidateIPv6Packet(t *testing.T) {
	tests := []struct {
		name      string
		srcIP     string
		dstIP     string
		expectErr bool
	}{
		{
			name:      "Valid packet",
			srcIP:     "2001:db9::1",
			dstIP:     "2001:db9::2",
			expectErr: false,
		},
		{
			name:      "Link-local to global",
			srcIP:     "fe80::1",
			dstIP:     "2001:db9::2",
			expectErr: false,
		},
		{
			name:      "Multicast source (invalid)",
			srcIP:     "ff02::1",
			dstIP:     "2001:db9::2",
			expectErr: true,
		},
		{
			name:      "Unspecified destination",
			srcIP:     "2001:db9::1",
			dstIP:     "::",
			expectErr: true,
		},
		{
			name:      "Invalid source (loopback)",
			srcIP:     "::1",
			dstIP:     "2001:db9::2",
			expectErr: true,
		},
		{
			name:      "IPv4-mapped source",
			srcIP:     "::ffff:192.0.2.1",
			dstIP:     "2001:db9::2",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcIP := net.ParseIP(tt.srcIP)
			dstIP := net.ParseIP(tt.dstIP)
			err := ValidateIPv6Packet(srcIP, dstIP)
			if (err != nil) != tt.expectErr {
				t.Errorf("ValidateIPv6Packet(%s, %s) error = %v, expectErr %v", tt.srcIP, tt.dstIP, err, tt.expectErr)
			}
		})
	}
}

func TestValidateDHCPv6Request(t *testing.T) {
	tests := []struct {
		name      string
		srcIP     string
		expectErr bool
	}{
		{
			name:      "Link-local source (valid)",
			srcIP:     "fe80::1",
			expectErr: false,
		},
		{
			name:      "Unspecified source (valid for initial request)",
			srcIP:     "::",
			expectErr: false,
		},
		{
			name:      "Global unicast source (invalid)",
			srcIP:     "2001:db9::1",
			expectErr: true,
		},
		{
			name:      "Unique local source (invalid)",
			srcIP:     "fd00::1",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcIP := net.ParseIP(tt.srcIP)
			err := ValidateDHCPv6Request(srcIP)
			if (err != nil) != tt.expectErr {
				t.Errorf("ValidateDHCPv6Request(%s) error = %v, expectErr %v", tt.srcIP, err, tt.expectErr)
			}
		})
	}
}

func TestValidateICMPv6Source(t *testing.T) {
	tests := []struct {
		name      string
		srcIP     string
		icmpType  uint8
		expectErr bool
	}{
		{
			name:      "Link-local NS (valid)",
			srcIP:     "fe80::1",
			icmpType:  135, // Neighbor Solicitation
			expectErr: false,
		},
		{
			name:      "Unspecified NS (valid for DAD)",
			srcIP:     "::",
			icmpType:  135,
			expectErr: false,
		},
		{
			name:      "Global unicast NS (invalid)",
			srcIP:     "2001:db9::1",
			icmpType:  135,
			expectErr: true,
		},
		{
			name:      "Link-local RS (valid)",
			srcIP:     "fe80::1",
			icmpType:  133, // Router Solicitation
			expectErr: false,
		},
		{
			name:      "Global unicast Echo Request (valid - not NDP)",
			srcIP:     "2001:db9::1",
			icmpType:  128, // Echo Request
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srcIP := net.ParseIP(tt.srcIP)
			err := ValidateICMPv6Source(srcIP, tt.icmpType)
			if (err != nil) != tt.expectErr {
				t.Errorf("ValidateICMPv6Source(%s, %d) error = %v, expectErr %v", tt.srcIP, tt.icmpType, err, tt.expectErr)
			}
		})
	}
}

func BenchmarkValidateIPv6Address(b *testing.B) {
	ip := net.ParseIP("2001:db9::1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateIPv6Address(ip)
	}
}

func BenchmarkValidateIPv6Packet(b *testing.B) {
	srcIP := net.ParseIP("2001:db9::1")
	dstIP := net.ParseIP("2001:db9::2")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateIPv6Packet(srcIP, dstIP)
	}
}
