// Package relay implements the WCPOS cloud print relay: a multi-tenant
// front for Star CloudPRNT / Epson Server Direct Print polling printers,
// forwarding to registered WCPOS sites. TLS is terminated by the Coolify
// Traefik proxy in front of this container; the service itself speaks
// plain HTTP on a single port.
package relay

import (
	"encoding/hex"
	"errors"
	"time"
)

// Deployment is fixed (Coolify, auto-deploy on push), so every knob that
// used to be an env var is a constant — each env var is another way the
// deploy can fail. The single remaining input is RELAY_MASTER_SECRET.
const (
	// PublicBaseURL is the printer-facing origin. Its DNS must stay a plain
	// A record, never behind a CDN — a CDN edge in front of the relay would
	// recreate the exact TLS failure this service exists to fix.
	PublicBaseURL = "https://cloudprint.wcpos.com"
	// ListenAddr is the plain-HTTP address the Coolify proxy forwards to.
	ListenAddr = ":8080"
	// SitesPath is the registry location on the Coolify persistent volume.
	SitesPath = "/data/sites.json"
	// HeartbeatInterval is the maximum interval between origin polls per
	// printer; it bounds print latency when a hint is lost.
	HeartbeatInterval = 60 * time.Second
	// PendingTTL is the lifetime of a job-pending hint.
	PendingTTL = 120 * time.Second
)

// ParseMasterSecret validates RELAY_MASTER_SECRET, the service's only
// configuration. It derives every deterministic site_key, so it must stay
// stable for the life of the service (Coolify secret + password manager).
func ParseMasterSecret(hexSecret string) ([]byte, error) {
	secret, err := hex.DecodeString(hexSecret)
	if err != nil || len(secret) != 32 {
		return nil, errors.New("RELAY_MASTER_SECRET must be 64 hex characters (32 bytes)")
	}
	return secret, nil
}
