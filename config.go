// Package relay implements the WCPOS cloud print relay: a multi-tenant,
// printer-compatible TLS front for Star CloudPRNT / Epson Server Direct
// Print polling, forwarding to registered WCPOS sites.
package relay

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

type Config struct {
	ListenAddr        string        // RELAY_LISTEN (default ":8443")
	HealthAddr        string        // RELAY_HEALTH (default "127.0.0.1:8080", plain HTTP /healthz)
	CertFile          string        // RELAY_CERT
	KeyFile           string        // RELAY_KEY
	SitesPath         string        // RELAY_SITES (default "sites.json")
	PublicBaseURL     string        // RELAY_PUBLIC_URL, e.g. https://cloudprint.wcpos.com
	Mode              string        // RELAY_MODE: "transparent" (default) | "adaptive"
	MasterSecret      []byte        // RELAY_MASTER_SECRET: 64 hex chars (32 bytes)
	HeartbeatInterval time.Duration // RELAY_HEARTBEAT (default 60s)
	PendingTTL        time.Duration // RELAY_PENDING_TTL (default 120s)
}

func LoadConfig(getenv func(string) string) (*Config, error) {
	get := func(key, def string) string {
		if v := getenv(key); v != "" {
			return v
		}
		return def
	}
	secret, err := hex.DecodeString(getenv("RELAY_MASTER_SECRET"))
	if err != nil || len(secret) != 32 {
		return nil, errors.New("RELAY_MASTER_SECRET must be 64 hex characters (32 bytes)")
	}
	public := getenv("RELAY_PUBLIC_URL")
	if public == "" {
		return nil, errors.New("RELAY_PUBLIC_URL is required")
	}
	mode := get("RELAY_MODE", "transparent")
	if mode != "transparent" && mode != "adaptive" {
		return nil, fmt.Errorf("RELAY_MODE must be transparent or adaptive, got %q", mode)
	}
	heartbeat, err := time.ParseDuration(get("RELAY_HEARTBEAT", "60s"))
	if err != nil {
		return nil, fmt.Errorf("RELAY_HEARTBEAT: %w", err)
	}
	ttl, err := time.ParseDuration(get("RELAY_PENDING_TTL", "120s"))
	if err != nil {
		return nil, fmt.Errorf("RELAY_PENDING_TTL: %w", err)
	}
	return &Config{
		ListenAddr:        get("RELAY_LISTEN", ":8443"),
		HealthAddr:        get("RELAY_HEALTH", "127.0.0.1:8080"),
		CertFile:          getenv("RELAY_CERT"),
		KeyFile:           getenv("RELAY_KEY"),
		SitesPath:         get("RELAY_SITES", "sites.json"),
		PublicBaseURL:     public,
		Mode:              mode,
		MasterSecret:      secret,
		HeartbeatInterval: heartbeat,
		PendingTTL:        ttl,
	}, nil
}
