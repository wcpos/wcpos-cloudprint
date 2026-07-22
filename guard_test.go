package relay

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestIsPublicIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.178.29",
		"169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1", "192.0.0.170",
		"64:ff9b::7f00:1", "2002:7f00:1::", "198.18.0.1", "192.88.99.1", "240.0.0.1", "255.255.255.255",
	}
	for _, s := range blocked {
		if IsPublicIP(net.ParseIP(s)) {
			t.Errorf("%s must be blocked", s)
		}
	}
	allowed := []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946", "162.159.135.42"}
	for _, s := range allowed {
		if !IsPublicIP(net.ParseIP(s)) {
			t.Errorf("%s must be allowed", s)
		}
	}
	if IsPublicIP(nil) {
		t.Error("nil must be blocked")
	}
}

func TestSafeDialContextRefusesLoopback(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := SafeDialContext(ctx, "tcp", "localhost:443"); err == nil {
		t.Fatal("dialing localhost must fail")
	}
	if _, err := SafeDialContext(ctx, "tcp", "127.0.0.1:443"); err == nil {
		t.Fatal("dialing 127.0.0.1 must fail")
	}
}

func TestOriginClientDoesNotFollowRedirects(t *testing.T) {
	c := NewOriginClient(5 * time.Second)
	req, _ := http.NewRequest(http.MethodGet, "https://example.invalid/", nil)
	resp := &http.Response{StatusCode: 301}
	if err := c.CheckRedirect(req, nil); err != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect must return ErrUseLastResponse, got %v", err)
	}
	_ = resp
}
