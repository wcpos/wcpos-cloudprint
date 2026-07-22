package relay

import (
	"sync"
	"time"
)

// PollState is the in-memory adaptive-polling ledger. Losing it on restart
// is harmless: the worst case is one extra heartbeat-forwarded poll per
// printer.
type PollState struct {
	mu       sync.Mutex
	pending  map[string]time.Time // hinted-at time
	lastFwd  map[string]time.Time
	lastSeen map[string]time.Time
}

func NewPollState() *PollState {
	return &PollState{
		pending:  map[string]time.Time{},
		lastFwd:  map[string]time.Time{},
		lastSeen: map[string]time.Time{},
	}
}

func pkey(site, printer string) string { return site + "|" + printer }

func (p *PollState) Hint(site, printer string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.pending) > 50000 {
		p.pending = map[string]time.Time{}
	}
	p.pending[pkey(site, printer)] = now
}

func (p *PollState) Seen(site, printer string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.lastSeen) > 50000 {
		p.lastSeen = map[string]time.Time{}
	}
	p.lastSeen[pkey(site, printer)] = now
}

func (p *PollState) LastSeen(site, printer string) (time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.lastSeen[pkey(site, printer)]
	return t, ok
}

// ShouldForward decides whether a printer poll goes to the origin: yes when
// a live hint is pending or the reconciliation heartbeat is due (which also
// bounds print latency to `heartbeat` when a hint was lost).
func (p *PollState) ShouldForward(site, printer string, now time.Time, heartbeat, ttl time.Duration) bool {
	k := pkey(site, printer)
	p.mu.Lock()
	defer p.mu.Unlock()
	if hinted, ok := p.pending[k]; ok {
		if now.Sub(hinted) <= ttl {
			return true
		}
		delete(p.pending, k)
	}
	last, ok := p.lastFwd[k]
	return !ok || now.Sub(last) >= heartbeat
}

func (p *PollState) NoteForward(site, printer string, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.lastFwd) > 50000 {
		p.lastFwd = map[string]time.Time{}
	}
	p.lastFwd[pkey(site, printer)] = now
}

func (p *PollState) ClearPending(site, printer string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.pending, pkey(site, printer))
}
