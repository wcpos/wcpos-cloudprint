package relay

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClassifyBlock(t *testing.T) {
	mkResp := func(status int, hdr map[string]string) *http.Response {
		r := &http.Response{StatusCode: status, Header: http.Header{}}
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return r
	}
	cases := []struct {
		name   string
		resp   *http.Response
		body   string
		signal string
	}{
		{"plugin ok", mkResp(200, nil), `{"jobReady":false}`, ""},
		{"plugin error is not a block", mkResp(401, nil), `{"code":"wcpos_print_job_invalid_token"}`, ""},
		{"cf challenge", mkResp(403, map[string]string{"cf-mitigated": "challenge"}), "", "cloudflare-challenge"},
		{"waf 403", mkResp(403, nil), "Forbidden", "http-403"},
		{"rate limited", mkResp(429, nil), "", "http-429"},
		{"maintenance page", mkResp(503, nil), "<html>busy</html>", "http-503"},
		{"bare internal error", mkResp(500, nil), "oops", "http-500"},
		{"bare bad gateway", mkResp(502, nil), "oops", "http-502"},
		{"bare gateway timeout", mkResp(504, nil), "oops", "http-504"},
		{"plugin 500 is not a block", mkResp(500, nil), `{"code":"wcpos_internal_error"}`, ""},
		{"html where api expected", mkResp(200, nil), "<!DOCTYPE html><html>challenge</html>", "html-instead-of-api-response"},
		{"sdp xml is legitimate", mkResp(200, nil), `<response success="true" code="" status=""/>`, ""},
		{"soap envelope is legitimate", mkResp(200, nil), `<?xml version="1.0"?><s:Envelope></s:Envelope>`, ""},
	}
	for _, c := range cases {
		if got := classifyBlock(c.resp, []byte(c.body)); got != c.signal {
			t.Errorf("%s: classifyBlock = %q, want %q", c.name, got, c.signal)
		}
	}
}

func TestBreakerTripsSuppressesAndRecovers(t *testing.T) {
	var hits atomic.Int64
	blocking := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-json/wcpos/v1/print-jobs/relay-verification" {
			fmt.Fprint(w, `{"token":"tok-123"}`)
			return
		}
		if got := r.Header.Get("User-Agent"); got != relayUA {
			t.Errorf("origin must see relay UA, got %q", got)
		}
		hits.Add(1)
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "<html>Access denied by WAF</html>")
	}))
	defer blocking.Close()

	rl, key, now := adaptiveRelay(t, blocking)

	// Three heartbeat-due polls hit the blocking origin and trip the breaker.
	for i := 0; i < 3; i++ {
		*now = now.Add(2 * time.Minute)
		if w := printerPoll(rl, key); w.Code != 200 || !strings.Contains(w.Body.String(), `"jobReady":false`) {
			t.Fatalf("blocked poll %d must degrade to local no-job: %d %s", i, w.Code, w.Body)
		}
	}
	if hits.Load() != 3 {
		t.Fatalf("origin hits = %d, want 3", hits.Load())
	}

	// Breaker open: heartbeat-due polls stop reaching the origin.
	*now = now.Add(2 * time.Minute)
	printerPoll(rl, key)
	if hits.Load() != 3 {
		t.Fatalf("breaker open must suppress forwards, got %d hits", hits.Load())
	}
	if state, signal := rl.Health.Status(key, *now); state != "blocked" || signal != "http-403" {
		t.Fatalf("Status = %q %q, want blocked http-403", state, signal)
	}

	// After the cooldown the breaker half-opens and we probe again.
	*now = now.Add(6 * time.Minute)
	printerPoll(rl, key)
	if hits.Load() != 4 {
		t.Fatalf("post-cooldown poll must probe origin, got %d hits", hits.Load())
	}
}

func TestPluginErrorsDoNotTripBreaker(t *testing.T) {
	misconfigured := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-json/wcpos/v1/print-jobs/relay-verification" {
			fmt.Fprint(w, `{"token":"tok-123"}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"code":"wcpos_print_job_invalid_token","message":"Invalid printer token."}`)
	}))
	defer misconfigured.Close()

	rl, key, now := adaptiveRelay(t, misconfigured)
	for i := 0; i < 5; i++ {
		*now = now.Add(2 * time.Minute)
		printerPoll(rl, key)
	}
	if blocked, _ := rl.Health.Blocked(key, *now); blocked {
		t.Fatal("plugin-authored 401s must never trip the breaker")
	}
}

func TestStatusEndpointReportsOriginState(t *testing.T) {
	site, siteURL := fakeSite(t, "tok-123")
	rl := testRelay(t, site.Client())
	out := register(t, rl, siteURL, "tok-123")
	stored, _ := rl.Store.Get(out["site_key"])
	rl.Health.NoteBlock(out["site_key"], "cloudflare-challenge", rl.Now())
	rl.Health.NoteBlock(out["site_key"], "cloudflare-challenge", rl.Now())
	rl.Health.NoteBlock(out["site_key"], "cloudflare-challenge", rl.Now())

	ts := strconv.FormatInt(rl.Now().Unix(), 10)
	sig := Sign(mustHex(t, stored.HintSecret), http.MethodGet, "/api/status/"+out["site_key"], ts, []byte("front"))
	req := httptest.NewRequest(http.MethodGet, "/api/status/"+out["site_key"]+"?printer_id=front", nil)
	req.SetPathValue("key", out["site_key"])
	req.Header.Set("X-Relay-Timestamp", ts)
	req.Header.Set("X-Relay-Signature", sig)
	w := httptest.NewRecorder()
	rl.handleStatus(w, req)
	if !strings.Contains(w.Body.String(), `"origin_status":"blocked"`) ||
		!strings.Contains(w.Body.String(), `"origin_block_signal":"cloudflare-challenge"`) {
		t.Fatalf("status must surface the block: %s", w.Body)
	}
}
