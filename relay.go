package relay

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
)

// Relay bundles the service dependencies. Origin is injectable so tests can
// use httptest clients (the production client's SSRF dialer correctly
// refuses loopback); Now is injectable for deterministic time.
type Relay struct {
	Cfg    *Config
	Store  *Store
	State  *PollState
	Health *OriginHealth
	Origin *http.Client
	RegLim *Limiter // registration attempts, per client IP
	FwdLim *Limiter // origin forwards, per site_key
	Now    func() time.Time
}

func hexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
