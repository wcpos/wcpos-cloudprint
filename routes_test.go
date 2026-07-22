package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoutesWiring(t *testing.T) {
	rl := testRelay(t, nil)
	h := rl.Handler()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != 200 || w.Body.String() != "ok" {
		t.Fatalf("healthz = %d %q", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST healthz = %d, want 405", w.Code)
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("unknown path = %d, want 404", w.Code)
	}
}
