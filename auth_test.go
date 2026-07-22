package relay

import (
	"strconv"
	"testing"
	"time"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Unix(5000, 0)
	ts := strconv.FormatInt(now.Unix(), 10)
	body := []byte(`{"printer_id":"front"}`)
	sig := Sign(secret, ts, body)
	if err := VerifySignature(secret, ts, sig, body, now, 5*time.Minute); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := VerifySignature(secret, ts, sig, []byte("tampered"), now, 5*time.Minute); err == nil {
		t.Fatal("tampered body must fail")
	}
	if err := VerifySignature([]byte("wrong-secret-wrong-secret-wrong!"), ts, sig, body, now, 5*time.Minute); err == nil {
		t.Fatal("wrong secret must fail")
	}
	if err := VerifySignature(secret, ts, sig, body, now.Add(10*time.Minute), 5*time.Minute); err == nil {
		t.Fatal("stale timestamp must fail (replay window)")
	}
	if err := VerifySignature(secret, "not-a-number", sig, body, now, 5*time.Minute); err == nil {
		t.Fatal("garbage timestamp must fail")
	}
}
