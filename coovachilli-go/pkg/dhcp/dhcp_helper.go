package dhcp

import (
	"github.com/insomniacslk/dhcp/dhcpv6"
)

// CreateDHCPv6Reply est une fonction d'aide pour créer une réponse DHCPv6
// à partir d'une requête, en y ajoutant les options fournies.
func CreateDHCPv6Reply(request *dhcpv6.Message, msgType dhcpv6.MessageType, options ...dhcpv6.Option) (*dhcpv6.Message, error) {
	reply, err := dhcpv6.NewReplyFromMessage(request)
	if err != nil {
		return nil, err
	}
	reply.MessageType = msgType
	for _, opt := range options {
		reply.AddOption(opt)
	}
	return reply, nil
}