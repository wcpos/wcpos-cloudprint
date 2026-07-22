package relay

import (
	"sync"

	"golang.org/x/time/rate"
)

// Limiter is a per-key token bucket. The map is capped crudely: at 10k keys
// it resets, which momentarily refills everyone's bucket — acceptable for a
// service whose keys are site_keys and registration IPs, and far simpler
// than LRU bookkeeping.
type Limiter struct {
	mu      sync.Mutex
	buckets map[string]*rate.Limiter
	r       rate.Limit
	b       int
}

func NewLimiter(perSec float64, burst int) *Limiter {
	return &Limiter{buckets: map[string]*rate.Limiter{}, r: rate.Limit(perSec), b: burst}
}

func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) > 10000 {
		l.buckets = map[string]*rate.Limiter{}
	}
	bucket, ok := l.buckets[key]
	if !ok {
		bucket = rate.NewLimiter(l.r, l.b)
		l.buckets[key] = bucket
	}
	return bucket.Allow()
}
