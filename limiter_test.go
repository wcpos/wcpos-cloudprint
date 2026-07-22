package relay

import "testing"

func TestLimiterBurstThenBlocksPerKey(t *testing.T) {
	l := NewLimiter(1, 3) // 1/s, burst 3
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("call %d within burst must pass", i)
		}
	}
	if l.Allow("a") {
		t.Fatal("burst exhausted: must block")
	}
	if !l.Allow("b") { // independent key unaffected
		t.Fatal("other key must pass")
	}
}
