package relay

import (
	"encoding/json"
	"net/http"
	"time"
)

// Relay bundles the service dependencies. Origin is injectable so tests can
// use httptest clients (the production client's SSRF dialer correctly
// refuses loopback); Now is injectable for deterministic time.
type Relay struct {
	MasterSecret []byte // derives deterministic site keys
	Store        *Store
	State        *PollState
	Health       *OriginHealth
	Origin       *http.Client
	RegLim       *Limiter // registration attempts, per client IP
	FwdLim       *Limiter // origin forwards, per site_key
	FetchLim     *Limiter // payload fetches/results, per site_key
	Now          func() time.Time
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
