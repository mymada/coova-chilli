package cluster

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/crypto/blowfish"
)

const (
	// ChilliEtherType is the custom EtherType for cluster communication.
	// (Value taken from C source)
	ChilliEtherType = 0x888F

	// Message Types
	MsgTypeCmd   = 0x01
	MsgTypeInit  = 0x02
	MsgTypeHello = 0x03
)

// ChilliHeader is the cluster communication protocol header.
// It mirrors the C struct pkt_chillihdr_t.
type ChilliHeader struct {
	From  uint8
	Type  uint8
	State uint8
	// 1 byte padding for alignment
	_     byte
	Addr  [4]byte // IPv4 address
	MAC   [6]byte // MAC address
	// 2 bytes padding
	_     [2]byte
}

// ✅ SECURITY FIX CVE-003: Removed static IV
// Old vulnerable code:
// var iv = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
// Now using random IV per message for proper CBC mode security

// Serialize converts the ChilliHeader to a byte slice for transmission.
func (h *ChilliHeader) Serialize() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, h); err != nil {
		return nil, fmt.Errorf("failed to serialize ChilliHeader: %w", err)
	}
	return buf.Bytes(), nil
}

// DeserializeChilliHeader converts a byte slice back to a ChilliHeader.
func DeserializeChilliHeader(data []byte) (*ChilliHeader, error) {
	var h ChilliHeader
	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.BigEndian, &h); err != nil {
		return nil, fmt.Errorf("failed to deserialize ChilliHeader: %w", err)
	}
	return &h, nil
}

// Encrypt encrypts data using Blowfish CBC with a random IV.
// ✅ SECURITY FIX CVE-003: Each message now uses a unique random IV
func Encrypt(data, key []byte) ([]byte, error) {
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// ✅ Generate random IV for each encryption
	iv := make([]byte, blowfish.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// CBC requires padding to a multiple of the block size.
	// Blowfish block size is 8 bytes.
	padLen := blowfish.BlockSize - (len(data) % blowfish.BlockSize)
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	paddedData := append(data, padding...)

	encrypted := make([]byte, len(paddedData))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(encrypted, paddedData)

	// ✅ Prepend IV to ciphertext (standard practice for CBC mode)
	return append(iv, encrypted...), nil
}

// Decrypt decrypts data using Blowfish CBC.
// ✅ SECURITY FIX CVE-003: Now extracts IV from the message
func Decrypt(data, key []byte) ([]byte, error) {
	// ✅ Ensure we have at least one block (IV)
	if len(data) < blowfish.BlockSize {
		return nil, fmt.Errorf("ciphertext too short to contain IV")
	}

	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// ✅ Extract IV from the first block
	iv := data[:blowfish.BlockSize]
	ciphertext := data[blowfish.BlockSize:]

	if len(ciphertext)%blowfish.BlockSize != 0 {
		return nil, fmt.Errorf("encrypted data is not a multiple of the block size")
	}

	decrypted := make([]byte, len(ciphertext))
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(decrypted, ciphertext)

	// Unpad
	if len(decrypted) == 0 {
		return nil, fmt.Errorf("decrypted data is empty")
	}
	padLen := int(decrypted[len(decrypted)-1])
	if padLen > blowfish.BlockSize || padLen == 0 || padLen > len(decrypted) {
		return nil, fmt.Errorf("invalid padding")
	}
	return decrypted[:len(decrypted)-padLen], nil
}

// SendClusterMessage sends a message to the cluster broadcast address.
func (m *PeerManager) SendClusterMessage(msgType uint8) error {
	h := ChilliHeader{
		From:  uint8(m.localID),
		Type:  msgType,
		State: uint8(m.GetCurrentState()),
	}
	copy(h.MAC[:], m.localMAC)
	copy(h.Addr[:], m.localAddr.To4())

	payload, err := h.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize for send: %w", err)
	}

	encryptedPayload, err := Encrypt(payload, m.peerKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt for send: %w", err)
	}

	handle, err := pcap.OpenLive(m.iface.Name, 1500, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap open live failed: %w", err)
	}
	defer handle.Close()

	ethLayer := &layers.Ethernet{
		SrcMAC:       m.localMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Broadcast
		EthernetType: ChilliEtherType,
	}

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{}
	err = gopacket.SerializeLayers(buffer, opts, ethLayer, gopacket.Payload(encryptedPayload))
	if err != nil {
		return fmt.Errorf("failed to serialize layers: %w", err)
	}

	return handle.WritePacketData(buffer.Bytes())
}

// ListenForClusterMessages starts listening for cluster messages on the specified interface.
func (m *PeerManager) ListenForClusterMessages() {
	handle, err := pcap.OpenLive(m.iface.Name, 1500, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("pcap open live failed: %v", err)
	}
	defer handle.Close()

	// Set a BPF filter to only capture our custom EtherType
	bpfFilter := fmt.Sprintf("ether proto 0x%X", ChilliEtherType)
	if err := handle.SetBPFFilter(bpfFilter); err != nil {
		log.Fatalf("failed to set BPF filter: %v", err)
	}

	log.Printf("Listening for cluster messages on %s", m.iface.Name)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}
		eth, _ := ethLayer.(*layers.Ethernet)

		// Ignore our own packets
		if bytes.Equal(eth.SrcMAC, m.localMAC) {
			continue
		}

		decrypted, err := Decrypt(eth.Payload, m.peerKey)
		if err != nil {
			log.Printf("Failed to decrypt cluster message from %s: %v", eth.SrcMAC, err)
			continue
		}

		header, err := DeserializeChilliHeader(decrypted)
		if err != nil {
			log.Printf("Failed to deserialize cluster message from %s: %v", eth.SrcMAC, err)
			continue
		}

		log.Printf("Received cluster message type %d from peer %d", header.Type, header.From)

		var ipAddr net.IP = header.Addr[:]
		var macAddr net.HardwareAddr = header.MAC[:]
		m.UpdatePeerState(int(header.From), PeerState(header.State), macAddr, ipAddr)
	}
}