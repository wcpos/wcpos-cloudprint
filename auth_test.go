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
	method, path := "POST", "/api/hint/site-key"
	sig := Sign(secret, method, path, ts, body)
	if sig != "6f8a3b4ec396988eebb52c9599784c8e4ba20e6c6cedaf6f91f7c4c9efcbdd49" {
		t.Fatalf("signature = %q", sig)
	}
	if err := VerifySignature(secret, method, path, ts, sig, body, now, 5*time.Minute); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := VerifySignature(secret, method, path, ts, sig, []byte("tampered"), now, 5*time.Minute); err == nil {
		t.Fatal("tampered body must fail")
	}
	if err := VerifySignature(secret, "GET", path, ts, sig, body, now, 5*time.Minute); err == nil {
		t.Fatal("tampered method must fail")
	}
	if err := VerifySignature(secret, method, "/api/status/site-key", ts, sig, body, now, 5*time.Minute); err == nil {
		t.Fatal("tampered path must fail")
	}
	if err := VerifySignature([]byte("wrong-secret-wrong-secret-wrong!"), method, path, ts, sig, body, now, 5*time.Minute); err == nil {
		t.Fatal("wrong secret must fail")
	}
	if err := VerifySignature(secret, method, path, ts, sig, body, now.Add(10*time.Minute), 5*time.Minute); err == nil {
		t.Fatal("stale timestamp must fail (replay window)")
	}
	if err := VerifySignature(secret, method, path, "not-a-number", sig, body, now, 5*time.Minute); err == nil {
		t.Fatal("garbage timestamp must fail")
	}
}
