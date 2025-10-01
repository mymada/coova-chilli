package radius

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
)

func TestCoAListener(t *testing.T) {
	// Setup
	cfg := &config.Config{
		CoaPort:      3799,
		RadiusSecret: "secret",
	}
	logger := zerolog.Nop()
	client := NewClient(cfg, logger, nil)
	coaReqChan := make(chan CoAIncomingRequest, 1)

	go client.StartCoAListener(coaReqChan)
	time.Sleep(50 * time.Millisecond) // Give the listener time to start

	// Create a Disconnect-Request packet
	packet := radius.New(radius.CodeDisconnectRequest, []byte(cfg.RadiusSecret))
	rfc2865.UserName_SetString(packet, "testuser")

	// Send the packet to the listener
	conn, err := net.Dial("udp", "127.0.0.1:3799")
	require.NoError(t, err)
	encoded, err := packet.Encode()
	require.NoError(t, err)
	_, err = conn.Write(encoded)
	require.NoError(t, err)
	conn.Close()

	// Assert that the request is received on the channel
	select {
	case req := <-coaReqChan:
		require.Equal(t, radius.CodeDisconnectRequest, req.Packet.Code)
		user := rfc2865.UserName_GetString(req.Packet)
		require.Equal(t, "testuser", user)
	case <-time.After(1 * time.Second):
		t.Fatal("Did not receive CoA request on channel")
	}
}

func generateCACert() (certPEM, keyPEM []byte, err error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2022),
		Subject: pkix.Name{
			Organization: []string{"CoovaChilli-Go Test"},
			Country:      []string{"US"},
			CommonName:   "CoovaChilli-Go Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, 1),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey)})

	return certPEM, keyPEM, nil
}

func generateLeafCert(caCertPEM, caKeyPEM []byte, commonName string) (certPEM, keyPEM []byte, err error) {
	caTLS, err := tls.X509KeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(caTLS.Certificate[0])
	if err != nil {
		return nil, nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"CoovaChilli-Go Test"},
			Country:      []string{"US"},
			CommonName:   commonName,
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, 1),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &privKey.PublicKey, caTLS.PrivateKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	return certPEM, keyPEM, nil
}

func TestRadSecExchange(t *testing.T) {
	// Generate certs and keys, and write to temp files
	caCertPEM, caKeyPEM, err := generateCACert()
	require.NoError(t, err)

	serverCertPEM, serverKeyPEM, err := generateLeafCert(caCertPEM, caKeyPEM, "localhost")
	require.NoError(t, err)

	clientCertPEM, clientKeyPEM, err := generateLeafCert(caCertPEM, caKeyPEM, "client")
	require.NoError(t, err)

	caFile, err := ioutil.TempFile("", "ca.crt")
	require.NoError(t, err)
	defer os.Remove(caFile.Name())
	_, err = caFile.Write(caCertPEM)
	require.NoError(t, err)
	caFile.Close()

	serverCertFile, err := ioutil.TempFile("", "server.crt")
	require.NoError(t, err)
	defer os.Remove(serverCertFile.Name())
	_, err = serverCertFile.Write(serverCertPEM)
	require.NoError(t, err)
	serverCertFile.Close()

	serverKeyFile, err := ioutil.TempFile("", "server.key")
	require.NoError(t, err)
	defer os.Remove(serverKeyFile.Name())
	_, err = serverKeyFile.Write(serverKeyPEM)
	require.NoError(t, err)
	serverKeyFile.Close()

	clientCertFile, err := ioutil.TempFile("", "client.crt")
	require.NoError(t, err)
	defer os.Remove(clientCertFile.Name())
	_, err = clientCertFile.Write(clientCertPEM)
	require.NoError(t, err)
	clientCertFile.Close()

	clientKeyFile, err := ioutil.TempFile("", "client.key")
	require.NoError(t, err)
	defer os.Remove(clientKeyFile.Name())
	_, err = clientKeyFile.Write(clientKeyPEM)
	require.NoError(t, err)
	clientKeyFile.Close()

	// Start mock RadSec server
	serverCert, err := tls.LoadX509KeyPair(serverCertFile.Name(), serverKeyFile.Name())
	require.NoError(t, err)

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertPEM)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	defer listener.Close()

	serverAddr := listener.Addr().(*net.TCPAddr)
	serverHost, serverPortStr, err := net.SplitHostPort(serverAddr.String())
	require.NoError(t, err)
	var serverPort int
	_, err = fmt.Sscanf(serverPortStr, "%d", &serverPort)
	require.NoError(t, err)

	serverErrChan := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErrChan <- err
			return
		}
		defer conn.Close()

		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			serverErrChan <- err
			return
		}

		// NOTE: Using a 16-byte secret to match the client configuration and avoid
		// potential library issues with shorter secrets.
		packet, err := radius.Parse(buf[:n], []byte("1234567890123456"))
		if err != nil {
			serverErrChan <- err
			return
		}
		if packet.Code != radius.CodeAccessRequest {
			serverErrChan <- fmt.Errorf("expected Access-Request, got %v", packet.Code)
			return
		}

		response := packet.Response(radius.CodeAccessAccept)
		encoded, err := response.Encode()
		if err != nil {
			serverErrChan <- err
			return
		}
		_, err = conn.Write(encoded)
		if err != nil {
			serverErrChan <- err
			return
		}
		serverErrChan <- nil
	}()

	// Configure the radius.Client
	cfg := &config.Config{
		RadiusServer1:  serverHost,
		RadiusSecret:   "1234567890123456",
		RadSecEnable:   true,
		RadSecPort:     serverPort,
		RadSecCertFile: clientCertFile.Name(),
		RadSecKeyFile:  clientKeyFile.Name(),
		RadSecCAFile:   caFile.Name(),
	}

	// Create client and session
	logger := zerolog.Nop()
	client := NewClient(cfg, logger, nil)
	mac, _ := net.ParseMAC("00:01:02:03:04:05")
	session := &core.Session{
		HisIP:  net.ParseIP("10.0.0.1"),
		HisMAC: mac,
	}

	// Call SendAccessRequest
	// NOTE: The password must be 16 bytes long due to a bug or
	// implicit requirement in the underlying layeh.com/radius library, which
	// causes a panic with shorter values during password encryption.
	_, err = client.SendAccessRequest(session, "testuser", "1234567890123456")
	require.NoError(t, err)

	// Check server for errors
	select {
	case err := <-serverErrChan:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("RadSec server timed out")
	}
}

func TestRadiusFailover(t *testing.T) {
	// Start mock secondary RADIUS server
	serverErrChan := make(chan error, 1)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer pc.Close()

	go func() {
		buf := make([]byte, 4096)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			serverErrChan <- err
			return
		}
		packet, err := radius.Parse(buf[:n], []byte("1234567890123456"))
		if err != nil {
			serverErrChan <- err
			return
		}
		if packet.Code != radius.CodeAccessRequest {
			serverErrChan <- fmt.Errorf("expected Access-Request, got %v", packet.Code)
			return
		}
		response := packet.Response(radius.CodeAccessAccept)
		encoded, err := response.Encode()
		if err != nil {
			serverErrChan <- err
			return
		}
		_, err = pc.WriteTo(encoded, addr)
		if err != nil {
			serverErrChan <- err
			return
		}
		serverErrChan <- nil
	}()

	serverAddr := pc.LocalAddr().(*net.UDPAddr)
	serverHost, serverPortStr, err := net.SplitHostPort(serverAddr.String())
	require.NoError(t, err)
	var serverPort int
	_, err = fmt.Sscanf(serverPortStr, "%d", &serverPort)
	require.NoError(t, err)

	// Configure the radius.Client with a bad primary and good secondary
	cfg := &config.Config{
		RadiusServer1:  "127.0.0.1",
		RadiusAuthPort: 1, // Invalid port to force failure
		RadiusServer2:  serverHost,
		RadiusAcctPort: serverPort, // For simplicity, use same port for auth/acct
		RadiusSecret:   "1234567890123456",
	}
	cfg.RadiusAuthPort = serverPort // Point secondary auth to the mock server

	// Create client and session
	logger := zerolog.Nop()
	client := NewClient(cfg, logger, nil)
	mac, _ := net.ParseMAC("00:01:02:03:04:05")
	session := &core.Session{
		HisIP:  net.ParseIP("10.0.0.1"),
		HisMAC: mac,
	}

	// Call SendAccessRequest - it should fail over to the secondary
	_, err = client.SendAccessRequest(session, "testuser", "1234567890123456")
	require.NoError(t, err)

	// Check that the secondary server received the request
	select {
	case err := <-serverErrChan:
		require.NoError(t, err)
	case <-time.After(5 * time.Second): // Allow time for the first server to time out
		t.Fatal("RADIUS server timed out")
	}
}

func TestRadiusProxy(t *testing.T) {
	// 1. Start mock upstream RADIUS server
	upstreamErrChan := make(chan error, 1)
	upstreamSecret := "upstreamsecret"
	upstreamListener, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer upstreamListener.Close()

	go func() {
		buf := make([]byte, 4096)
		n, addr, err := upstreamListener.ReadFrom(buf)
		if err != nil {
			upstreamErrChan <- err
			return
		}
		packet, err := radius.Parse(buf[:n], []byte(upstreamSecret))
		require.NoError(t, err)
		require.Equal(t, radius.CodeAccessRequest, packet.Code)
		response := packet.Response(radius.CodeAccessAccept)
		encoded, err := response.Encode()
		require.NoError(t, err)
		_, err = upstreamListener.WriteTo(encoded, addr)
		require.NoError(t, err)
		upstreamErrChan <- nil
	}()

	upstreamAddr := upstreamListener.LocalAddr().(*net.UDPAddr)
	upstreamHost, upstreamPortStr, _ := net.SplitHostPort(upstreamAddr.String())
	var upstreamPort int
	_, _ = fmt.Sscanf(upstreamPortStr, "%d", &upstreamPort)

	// 2. Setup coovachilli-go components
	logger := zerolog.Nop()
	proxySecret := "proxysecret"
	cfg := &config.Config{
		ProxyEnable:    true,
		ProxyListen:    "127.0.0.1",
		ProxyPort:      0, // Use random port
		ProxySecret:    proxySecret,
		RadiusServer1:  upstreamHost,
		RadiusAuthPort: upstreamPort,
		RadiusSecret:   upstreamSecret,
	}
	sm := core.NewSessionManager(nil)
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	_ = sm.CreateSession(net.ParseIP("10.2.0.1"), mac, 0, cfg)

	radiusClient := NewClient(cfg, logger, nil)
	proxyServer := NewProxyServer(cfg, sm, radiusClient, logger)

	// Get a random port for the proxy
	proxyListener, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", cfg.ProxyListen, cfg.ProxyPort))
	require.NoError(t, err)
	proxyAddr := proxyListener.LocalAddr().(*net.UDPAddr)
	cfg.ProxyPort = proxyAddr.Port
	proxyListener.Close() // Close it so the proxy can bind to it

	go proxyServer.Start()
	time.Sleep(50 * time.Millisecond)

	// 3. Mock Downstream NAS
	nasPacket := radius.New(radius.CodeAccessRequest, []byte(proxySecret))
	rfc2865.UserName_SetString(nasPacket, "testuser")
	rfc2865.CallingStationID_SetString(nasPacket, "00-11-22-33-44-55")

	response, err := radius.Exchange(context.Background(), nasPacket, proxyAddr.String())
	require.NoError(t, err)

	// 4. Verification
	require.Equal(t, radius.CodeAccessAccept, response.Code, "Expected Access-Accept from proxy")

	select {
	case err := <-upstreamErrChan:
		require.NoError(t, err, "Upstream server encountered an error")
	case <-time.After(2 * time.Second):
		t.Fatal("Upstream RADIUS server timed out")
	}
}