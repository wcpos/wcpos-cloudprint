package relay

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeOrigin counts hits and scripts poll answers per call.
type fakeOrigin struct {
	polls   atomic.Int64
	gets    atomic.Int64
	deletes atomic.Int64
	ready   atomic.Bool
}

func newFakeOrigin(t *testing.T) (*fakeOrigin, *httptest.Server) {
	t.Helper()
	fo := &fakeOrigin{}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/wp-json/wcpos/v1/print-jobs/relay-verification":
			fmt.Fprint(w, `{"token":"tok-123"}`)
		case r.URL.Path == "/wp-json/wcpos/v1/print-jobs/cloudprnt" && r.Method == http.MethodPost:
			fo.polls.Add(1)
			if fo.ready.Load() {
				fmt.Fprint(w, `{"jobReady":true,"jobToken":"7","mediaType":"application/octet-stream"}`)
			} else {
				fmt.Fprint(w, `{"jobReady":false}`)
			}
		case r.URL.Path == "/wp-json/wcpos/v1/print-jobs/cloudprnt" && r.Method == http.MethodGet:
			fo.gets.Add(1)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Write([]byte{0x1b, 0x40, 'W', 'C', 'P', 'O', 'S'})
		case r.URL.Path == "/wp-json/wcpos/v1/print-jobs/cloudprnt" && r.Method == http.MethodDelete:
			fo.deletes.Add(1)
			fmt.Fprint(w, `{"ok":true}`)
		case r.URL.Path == "/wp-json/wcpos/v1/print-jobs/epson-sdp":
			fmt.Fprint(w, `<response success="true" code="" status=""/>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return fo, ts
}

func adaptiveRelay(t *testing.T, ts *httptest.Server) (*Relay, string, *time.Time) {
	t.Helper()
	rl := testRelay(t, ts.Client())
	rl.Cfg.Mode = "adaptive"
	now := time.Unix(50000, 0)
	rl.Now = func() time.Time { return now }
	out := register(t, rl, ts.URL, "tok-123")
	return rl, out["site_key"], &now
}

func printerPoll(rl *Relay, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/p/"+key+"/cloudprnt?printer_id=front&pt=secret-token",
		strings.NewReader(`{"status":"23 6 0 0 0 0 0 0 0"}`))
	req.SetPathValue("key", key)
	w := httptest.NewRecorder()
	rl.handleCloudPRNT(w, req)
	return w
}

func TestAdaptivePollAbsorbsIdlePolls(t *testing.T) {
	fo, ts := newFakeOrigin(t)
	rl, key, now := adaptiveRelay(t, ts)

	// Poll 1: heartbeat due (never forwarded) -> origin hit.
	if w := printerPoll(rl, key); !strings.Contains(w.Body.String(), `"jobReady":false`) {
		t.Fatalf("poll 1 body: %s", w.Body)
	}
	// Polls 2-4 within heartbeat: absorbed locally.
	for i := 0; i < 3; i++ {
		*now = now.Add(5 * time.Second)
		if w := printerPoll(rl, key); w.Code != 200 || !strings.Contains(w.Body.String(), `"jobReady":false`) {
			t.Fatalf("absorbed poll %d: %d %s", i, w.Code, w.Body)
		}
	}
	if got := fo.polls.Load(); got != 1 {
		t.Fatalf("origin polls = %d, want 1 (idle polls absorbed)", got)
	}
}

func TestHintForwardsNextPollAndDrainClears(t *testing.T) {
	fo, ts := newFakeOrigin(t)
	rl, key, now := adaptiveRelay(t, ts)
	printerPoll(rl, key) // consume initial heartbeat

	fo.ready.Store(true)
	rl.State.Hint(key, "front", *now)
	*now = now.Add(5 * time.Second)
	if w := printerPoll(rl, key); !strings.Contains(w.Body.String(), `"jobReady":true`) {
		t.Fatalf("hinted poll must reach origin and return the job: %s", w.Body)
	}
	// Queue drains -> next forwarded poll returns false and clears pending.
	fo.ready.Store(false)
	*now = now.Add(5 * time.Second)
	printerPoll(rl, key) // pending still set: forwards, sees false, clears
	before := fo.polls.Load()
	*now = now.Add(5 * time.Second)
	printerPoll(rl, key) // absorbed again
	if fo.polls.Load() != before {
		t.Fatal("poll after drain must be absorbed locally")
	}
}

func TestGetAndDeleteAlwaysForward(t *testing.T) {
	fo, ts := newFakeOrigin(t)
	rl, key, _ := adaptiveRelay(t, ts)

	req := httptest.NewRequest(http.MethodGet, "/p/"+key+"/cloudprnt?printer_id=front&pt=x&token=7", nil)
	req.SetPathValue("key", key)
	w := httptest.NewRecorder()
	rl.handleCloudPRNT(w, req)
	if w.Code != 200 || !bytes.HasPrefix(w.Body.Bytes(), []byte{0x1b, 0x40}) {
		t.Fatalf("GET payload = %d %q", w.Code, w.Body.Bytes())
	}
	if w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("content-type not forwarded: %q", w.Header().Get("Content-Type"))
	}

	req = httptest.NewRequest(http.MethodDelete, "/p/"+key+"/cloudprnt?printer_id=front&pt=x&token=7&code=200%20OK", nil)
	req.SetPathValue("key", key)
	w = httptest.NewRecorder()
	rl.handleCloudPRNT(w, req)
	if w.Code != 200 {
		t.Fatalf("DELETE = %d", w.Code)
	}
	if fo.gets.Load() != 1 || fo.deletes.Load() != 1 {
		t.Fatalf("gets=%d deletes=%d, want 1/1", fo.gets.Load(), fo.deletes.Load())
	}
}

func TestUnknownSiteAndOriginDownAreSafe(t *testing.T) {
	_, ts := newFakeOrigin(t)
	rl, key, now := adaptiveRelay(t, ts)

	// Unknown site_key -> 404, nothing forwarded.
	req := httptest.NewRequest(http.MethodPost, "/p/ffffffffffffffffffffffffffffffff/cloudprnt?printer_id=x", nil)
	req.SetPathValue("key", "ffffffffffffffffffffffffffffffff")
	w := httptest.NewRecorder()
	rl.handleCloudPRNT(w, req)
	if w.Code != 404 {
		t.Fatalf("unknown site = %d, want 404", w.Code)
	}

	// Origin down: poll gets a calm local "no job", never a 5xx.
	ts.Close()
	*now = now.Add(2 * time.Hour) // heartbeat due -> forward attempted -> fails
	if w := printerPoll(rl, key); w.Code != 200 || !strings.Contains(w.Body.String(), `"jobReady":false`) {
		t.Fatalf("origin-down poll = %d %s, want local jobReady:false", w.Code, w.Body)
	}
}

func TestSDPResultAlwaysForwardsPollGated(t *testing.T) {
	_, ts := newFakeOrigin(t)
	rl, key, now := adaptiveRelay(t, ts)

	sdp := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/p/"+key+"/epson-sdp?printer_id=ep1&pt=x",
			strings.NewReader(body))
		req.SetPathValue("key", key)
		w := httptest.NewRecorder()
		rl.handleSDP(w, req)
		return w
	}
	sdp("") // heartbeat consumed
	*now = now.Add(5 * time.Second)
	if w := sdp(""); !strings.Contains(w.Body.String(), `success="true"`) {
		t.Fatalf("gated SDP poll must get local ack: %s", w.Body)
	}
	// Result report is never gated even inside the heartbeat window.
	if w := sdp(`ResponseFile=<response success="true" code="" status=""/>`); w.Code != 200 {
		t.Fatalf("SDP result forward = %d", w.Code)
	}
}
