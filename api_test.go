package relay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testRelay(t *testing.T, originClient *http.Client) *Relay {
	t.Helper()
	cfg, err := LoadConfig(fakeEnv(map[string]string{
		"RELAY_MASTER_SECRET": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
		"RELAY_PUBLIC_URL":    "https://cloudprint.wcpos.com",
	}))
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(t.TempDir() + "/sites.json")
	if err != nil {
		t.Fatal(err)
	}
	return &Relay{
		Cfg: cfg, Store: store, State: NewPollState(), Origin: originClient,
		Health: NewOriginHealth(),
		RegLim: NewLimiter(100, 100), FwdLim: NewLimiter(100, 100), FetchLim: NewLimiter(100, 100),
		Now: func() time.Time { return time.Unix(9000, 0) },
	}
}

// fakeSite pretends to be a WCPOS install exposing the verification endpoint.
func fakeSite(t *testing.T, verifyToken string) (*httptest.Server, string) {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-json/wcpos/v1/print-jobs/relay-verification" {
			fmt.Fprintf(w, `{"token":%q}`, verifyToken)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts, ts.URL
}

func register(t *testing.T, rl *Relay, siteURL, token string) map[string]string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"site_url": siteURL, "verify_token": token})
	req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.5:1234"
	w := httptest.NewRecorder()
	rl.handleRegister(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("register = %d: %s", w.Code, w.Body)
	}
	var out map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRegisterVerifiesSiteAndIssuesKey(t *testing.T) {
	site, siteURL := fakeSite(t, "tok-123")
	rl := testRelay(t, site.Client())
	out := register(t, rl, siteURL, "tok-123")
	if len(out["site_key"]) != 32 || len(out["hint_secret"]) != 64 {
		t.Fatalf("bad credential shapes: %+v", out)
	}
	if !strings.HasPrefix(out["printer_base_url"], "https://cloudprint.wcpos.com/p/") {
		t.Fatalf("bad printer_base_url: %q", out["printer_base_url"])
	}
	if _, ok := rl.Store.Get(out["site_key"]); !ok {
		t.Fatal("site must be persisted")
	}
}

func TestRegisterRejectsWrongTokenAndBadOrigin(t *testing.T) {
	site, siteURL := fakeSite(t, "tok-123")
	rl := testRelay(t, site.Client())
	for name, in := range map[string]map[string]string{
		"wrong token": {"site_url": siteURL, "verify_token": "nope"},
		"http origin": {"site_url": "http://example.com", "verify_token": "tok-123"},
	} {
		body, _ := json.Marshal(in)
		req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(body))
		req.RemoteAddr = "203.0.113.5:1234"
		w := httptest.NewRecorder()
		rl.handleRegister(w, req)
		if w.Code < 400 {
			t.Errorf("%s: want 4xx, got %d", name, w.Code)
		}
	}
}

func TestHintRequiresValidSignatureAndSetsPending(t *testing.T) {
	site, siteURL := fakeSite(t, "tok-123")
	rl := testRelay(t, site.Client())
	out := register(t, rl, siteURL, "tok-123")
	stored, _ := rl.Store.Get(out["site_key"])

	body := []byte(`{"printer_id":"front"}`)
	ts := strconv.FormatInt(rl.Now().Unix(), 10)
	mkReq := func(sig string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/hint/"+out["site_key"], bytes.NewReader(body))
		req.SetPathValue("key", out["site_key"])
		req.Header.Set("X-Relay-Timestamp", ts)
		req.Header.Set("X-Relay-Signature", sig)
		w := httptest.NewRecorder()
		rl.handleHint(w, req)
		return w
	}

	if w := mkReq("bad-signature"); w.Code != http.StatusUnauthorized {
		t.Fatalf("bad sig = %d, want 401", w.Code)
	}
	secret := mustHex(t, stored.HintSecret)
	if w := mkReq(Sign(secret, http.MethodPost, "/api/hint/"+out["site_key"], ts, body)); w.Code != http.StatusNoContent {
		t.Fatalf("good sig = %d, want 204", w.Code)
	}
	if !rl.State.ShouldForward(out["site_key"], "front", rl.Now(), time.Hour, 2*time.Minute) {
		t.Fatal("hint must set the pending flag")
	}
}

func TestStatusReportsLastSeen(t *testing.T) {
	site, siteURL := fakeSite(t, "tok-123")
	rl := testRelay(t, site.Client())
	out := register(t, rl, siteURL, "tok-123")
	stored, _ := rl.Store.Get(out["site_key"])
	rl.State.Seen(out["site_key"], "front", rl.Now().Add(-42*time.Second))

	ts := strconv.FormatInt(rl.Now().Unix(), 10)
	sig := Sign(mustHex(t, stored.HintSecret), http.MethodGet, "/api/status/"+out["site_key"], ts, []byte("front"))
	req := httptest.NewRequest(http.MethodGet, "/api/status/"+out["site_key"]+"?printer_id=front", nil)
	req.SetPathValue("key", out["site_key"])
	req.Header.Set("X-Relay-Timestamp", ts)
	req.Header.Set("X-Relay-Signature", sig)
	w := httptest.NewRecorder()
	rl.handleStatus(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body)
	}
	var got struct {
		PrinterID   string `json:"printer_id"`
		LastSeenAgo *int64 `json:"last_seen_seconds_ago"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.LastSeenAgo == nil || *got.LastSeenAgo != 42 {
		t.Fatalf("last_seen_seconds_ago = %v, want 42", got.LastSeenAgo)
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
