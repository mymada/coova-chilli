package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"coovachilli-go/pkg/config"
	"coovachilli-go/pkg/core"
	"coovachilli-go/pkg/dhcp"
	"coovachilli-go/pkg/firewall"
	"coovachilli-go/pkg/http"
	"coovachilli-go/pkg/radius"
	"coovachilli-go/pkg/tun"
	"layeh.com/radius/rfc2866"
)

func main() {
	fmt.Println("Starting CoovaChilli-Go...")

	cfg, err := config.Load("coovachilli-go/config.yaml")
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	fw, err := firewall.NewFirewall(cfg)
	if err != nil {
		log.Fatalf("Error creating firewall manager: %v", err)
	}
	if err := fw.Initialize(); err != nil {
		log.Fatalf("Error initializing firewall: %v", err)
	}
	defer fw.Cleanup()

	sessionManager := core.NewSessionManager()
	radiusReqChan := make(chan *core.Session)
	radiusClient := radius.NewClient(cfg)

	_, err = dhcp.NewServer(cfg, sessionManager, radiusReqChan)
	if err != nil {
		log.Fatalf("Error creating DHCP server: %v", err)
	}

	httpServer := http.NewServer(cfg, sessionManager, radiusReqChan)
	go httpServer.Start()

	ifce, err := tun.New(cfg)
	if err != nil {
		log.Fatalf("Error creating TUN interface: %v", err)
	}

	packetChan := make(chan []byte)
	go tun.ReadPackets(ifce, packetChan)

	// RADIUS processing loop
	go func() {
		for session := range radiusReqChan {
			log.Printf("Processing RADIUS request for session: %s", session.SessionID)
			resp, err := radiusClient.SendAccessRequest(session, session.Redir.Username, session.Redir.Password)
			if err != nil {
				log.Printf("Error sending RADIUS Access-Request: %v", err)
				continue
			}

			if resp.Code == "Access-Accept" {
				log.Printf("RADIUS Access-Accept for user %s", session.Redir.Username)
				session.Lock()
				session.Authenticated = true
				session.Unlock()

				if err := fw.AddAuthenticatedUser(session.HisIP); err != nil {
					log.Printf("Error adding firewall rule for user %s: %v", session.Redir.Username, err)
				}

				// Send accounting start
				go radiusClient.SendAccountingRequest(session, rfc2866.AcctStatusType_Start)
			} else {
				log.Printf("RADIUS Access-Reject for user %s", session.Redir.Username)
			}
		}
	}()

	// Packet dispatcher
	go func() {
		for packet := range packetChan {
			log.Printf("Received packet of size %d from TUN", len(packet))
			// This dispatcher will handle packets coming from clients via the TUN
		}
	}()

	fmt.Println("CoovaChilli-Go is running. Press Ctrl-C to stop.")

	// Graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("Shutting down CoovaChilli-Go...")

	// Perform cleanup tasks here
	// For example, send accounting stop for all active sessions
	for _, session := range sessionManager.GetAllSessions() {
		if session.Authenticated {
			radiusClient.SendAccountingRequest(session, rfc2866.AcctStatusType_Stop)
		}
	}

	// The deferred fw.Cleanup() will run now
}
