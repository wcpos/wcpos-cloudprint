package relay

import (
	"sync"
	"time"
)

// OriginHealth is the per-site circuit breaker for the origin leg (D9).
// When a CDN, WAF, or security plugin starts blocking the relay we stop
// hammering it — continued traffic escalates temporary blocks into IP
// reputation bans — and surface the signal via /api/status so the site
// owner can allowlist us. State is in-memory; losing it on restart merely
// re-probes each origin once.
type OriginHealth struct {
	mu    sync.Mutex
	sites map[string]*originState
}

type originState struct {
	consecutive int
	blockedTill time.Time
	signal      string
	lastOK      time.Time
}

const (
	blockThreshold = 3
	blockCooldown  = 5 * time.Minute
)

func NewOriginHealth() *OriginHealth {
	return &OriginHealth{sites: map[string]*originState{}}
}

func (h *OriginHealth) get(site string) *originState {
	s, ok := h.sites[site]
	if !ok {
		s = &originState{}
		h.sites[site] = s
	}
	return s
}

func (h *OriginHealth) NoteOK(site string, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.get(site)
	s.consecutive, s.signal, s.blockedTill = 0, "", time.Time{}
	s.lastOK = now
}

func (h *OriginHealth) NoteBlock(site, signal string, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.get(site)
	s.consecutive++
	s.signal = signal
	if s.consecutive >= blockThreshold {
		s.blockedTill = now.Add(blockCooldown)
	}
}

// Blocked reports whether forwards to this origin are currently suspended.
// After the cooldown it returns false again (half-open: the next poll probes).
func (h *OriginHealth) Blocked(site string, now time.Time) (bool, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.get(site)
	return now.Before(s.blockedTill), s.signal
}

// Status is the /api/status view: "ok" | "blocked" | "unknown".
func (h *OriginHealth) Status(site string, now time.Time) (string, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.sites[site]
	if !ok || (s.lastOK.IsZero() && s.signal == "") {
		return "unknown", ""
	}
	if now.Before(s.blockedTill) {
		return "blocked", s.signal
	}
	if s.lastOK.IsZero() {
		// Never a successful forward: a lingering signal means it has only
		// ever failed; otherwise the state is simply not yet known.
		if s.signal != "" {
			return "blocked", s.signal
		}
		return "unknown", ""
	}
	return "ok", s.signal
}
