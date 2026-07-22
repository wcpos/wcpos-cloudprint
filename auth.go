package relay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"
)

// Sign computes the request signature the plugin sends on /api/hint and
// /api/status calls: hex(HMAC-SHA256(secret, method + "\n" + path + "\n" + ts + "\n" + payload)).
func Sign(secret []byte, method, path, ts string, payload []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(method))
	mac.Write([]byte("\n"))
	mac.Write([]byte(path))
	mac.Write([]byte("\n"))
	mac.Write([]byte(ts))
	mac.Write([]byte("\n"))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignature checks the signature and enforces a replay window. A
// replayed hint is nearly harmless (one extra origin poll) but there is no
// reason to allow it.
func VerifySignature(secret []byte, method, path, ts, sig string, payload []byte, now time.Time, skew time.Duration) error {
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return errors.New("invalid timestamp")
	}
	if d := now.Sub(time.Unix(sec, 0)); d > skew || d < -skew {
		return errors.New("timestamp outside allowed window")
	}
	if !hmac.Equal([]byte(Sign(secret, method, path, ts, payload)), []byte(sig)) {
		return errors.New("invalid signature")
	}
	return nil
}
