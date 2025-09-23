package dhcp

import (
	"net"
	"testing"
)

func TestPool(t *testing.T) {
	start := net.ParseIP("10.1.0.100")
	end := net.ParseIP("10.1.0.102")

	pool, err := NewPool(start, end)
	if err != nil {
		t.Fatalf("NewPool failed: %v", err)
	}

	// Test getFreeIP
	ip1, err := pool.getFreeIP()
	if err != nil {
		t.Fatalf("getFreeIP failed: %v", err)
	}
	if !ip1.Equal(start) {
		t.Fatalf("getFreeIP returned wrong IP: got %s, want %s", ip1, start)
	}

	ip2, err := pool.getFreeIP()
	if err != nil {
		t.Fatalf("getFreeIP failed: %v", err)
	}
	if !ip2.Equal(net.ParseIP("10.1.0.101")) {
		t.Fatalf("getFreeIP returned wrong IP: got %s, want %s", ip2, "10.1.0.101")
	}

	// Test pool exhaustion
	_, err = pool.getFreeIP()
	if err == nil {
		t.Fatal("getFreeIP should have failed when pool is exhausted")
	}
}
