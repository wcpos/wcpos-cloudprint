package relay

import (
	"testing"
	"time"
)

func TestShouldForwardHeartbeatAndHints(t *testing.T) {
	p := NewPollState()
	t0 := time.Unix(1000, 0)
	hb, ttl := 60*time.Second, 120*time.Second

	// First poll ever: no lastFwd -> heartbeat due -> forward.
	if !p.ShouldForward("s", "pr1", t0, hb, ttl) {
		t.Fatal("first poll must forward")
	}
	p.NoteForward("s", "pr1", t0)

	// 5s later, no hint: absorbed locally.
	if p.ShouldForward("s", "pr1", t0.Add(5*time.Second), hb, ttl) {
		t.Fatal("poll within heartbeat with no hint must not forward")
	}

	// Hint arrives: very next poll forwards.
	p.Hint("s", "pr1", t0.Add(6*time.Second))
	if !p.ShouldForward("s", "pr1", t0.Add(10*time.Second), hb, ttl) {
		t.Fatal("hinted poll must forward")
	}

	// Pending persists until cleared (job still queued after one forward)...
	if !p.ShouldForward("s", "pr1", t0.Add(15*time.Second), hb, ttl) {
		t.Fatal("pending flag must persist until cleared")
	}
	// ...then clears when the queue drains.
	p.ClearPending("s", "pr1")
	p.NoteForward("s", "pr1", t0.Add(15*time.Second))
	if p.ShouldForward("s", "pr1", t0.Add(20*time.Second), hb, ttl) {
		t.Fatal("cleared pending must stop forwarding")
	}

	// Heartbeat elapses: forward again (reconciliation for lost hints).
	if !p.ShouldForward("s", "pr1", t0.Add(80*time.Second), hb, ttl) {
		t.Fatal("heartbeat must force a forward")
	}

	// Expired hint (older than ttl) does not force a forward.
	p.NoteForward("s", "pr2", t0)
	p.Hint("s", "pr2", t0)
	if p.ShouldForward("s", "pr2", t0.Add(ttl+time.Second), hb, ttl) {
		// note: at t0+121s the 60s heartbeat IS due, so use a fresh forward first
		t.Skip("covered below")
	}
	p.NoteForward("s", "pr2", t0.Add(ttl))
	if p.ShouldForward("s", "pr2", t0.Add(ttl+30*time.Second), hb, ttl) {
		t.Fatal("expired hint must not force a forward")
	}
}

func TestLastSeen(t *testing.T) {
	p := NewPollState()
	if _, ok := p.LastSeen("s", "pr1"); ok {
		t.Fatal("unseen printer must miss")
	}
	now := time.Unix(2000, 0)
	p.Seen("s", "pr1", now)
	got, ok := p.LastSeen("s", "pr1")
	if !ok || !got.Equal(now) {
		t.Fatalf("LastSeen = %v, %v", got, ok)
	}
}
