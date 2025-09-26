package dhcp

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/stretchr/testify/require"
)

func TestCreateDHCPv6Reply(t *testing.T) {
	clientMAC, _ := net.ParseMAC("00:00:5e:00:53:01")
	req, err := dhcpv6.NewMessage()
	require.NoError(t, err)
	req.MessageType = dhcpv6.MessageTypeSolicit
	req.AddOption(dhcpv6.OptClientID(&dhcpv6.DUIDLL{LinkLayerAddr: clientMAC}))
	req.AddOption(&dhcpv6.OptionGeneric{OptionCode: dhcpv6.OptionRapidCommit, OptionData: []byte{}})

	dnsOpt := dhcpv6.OptDNS(net.ParseIP("2001:4860:4860::8888"))

	reply, err := CreateDHCPv6Reply(req, dhcpv6.MessageTypeAdvertise, dnsOpt)
	require.NoError(t, err)
	require.NotNil(t, reply)

	require.Equal(t, dhcpv6.MessageTypeAdvertise, reply.MessageType)
	dnsServers := reply.Options.DNS()
	require.NotNil(t, dnsServers)
	require.Len(t, dnsServers, 1)
	require.True(t, dnsServers[0].Equal(net.ParseIP("2001:4860:4860::8888")))
}