package relay

import (
	"crypto/tls"
	"testing"
)

func TestTLSConfigFloorAndLegacySuites(t *testing.T) {
	c := TLSConfig()
	if c.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x, want TLS 1.2", c.MinVersion)
	}
	// Legacy printers need static-RSA and CBC suites (TSP100IV spec §10.3.2).
	need := []uint16{
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
	for _, want := range need {
		found := false
		for _, got := range c.CipherSuites {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("cipher %x missing", want)
		}
	}
}
