package relay

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })
	return &buf
}

func TestLogRequestsRedactsTokenAndRecordsMetadata(t *testing.T) {
	buf := captureLog(t)
	h := LogRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/p/abc123/cloudprnt?wcpos=1&printer_id=front&pt=super-secret-token", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	if strings.Contains(out, "super-secret-token") {
		t.Fatalf("pt token leaked into log: %q", out)
	}
	if !strings.Contains(out, "pt=<redacted>") {
		t.Fatalf("pt not redacted: %q", out)
	}
	for _, want := range []string{`method=POST`, `printer_id="front"`, `status=200`, `bytes=2`} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q in %q", want, out)
		}
	}
}

func TestLogRequestsSurfacesEmptyPrinterId(t *testing.T) {
	buf := captureLog(t)
	h := LogRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	// The Kanso failure mode: only wcpos=1 survives, printer_id/pt dropped.
	req := httptest.NewRequest(http.MethodPost, "/p/abc123/cloudprnt?wcpos=1", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !strings.Contains(buf.String(), `printer_id=""`) {
		t.Fatalf("empty printer_id not visible in log: %q", buf.String())
	}
}

func TestLogRequestsSkipsHealthz(t *testing.T) {
	buf := captureLog(t)
	h := LogRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if buf.Len() != 0 {
		t.Fatalf("healthz should not be logged, got: %q", buf.String())
	}
}

func TestLogRequestsRedactsPathTokenAndExtractsPrinter(t *testing.T) {
	buf := captureLog(t)
	h := LogRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodPost,
		"/p/abc123/front/super-secret-token/cloudprnt?t=1784822084", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	if strings.Contains(out, "super-secret-token") {
		t.Fatalf("path token leaked into log: %q", out)
	}
	if !strings.Contains(out, "path=/p/abc123/front/<redacted>/cloudprnt") {
		t.Fatalf("path token not redacted: %q", out)
	}
	if !strings.Contains(out, `printer_id="front"`) {
		t.Fatalf("printer id not extracted from path: %q", out)
	}
}
