package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoutesWiring(t *testing.T) {
	rl := testRelay(t, nil)
	h := rl.HealthHandler()

	// The health listener exposes only GET /healthz.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != 200 {
		t.Fatalf("healthz = %d", w.Code)
	}
	for _, path := range []string{"/", "/api/status/key", "/p/abc/cloudprnt"} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != 404 {
			t.Errorf("%s = %d, want 404", path, w.Code)
		}
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/healthz", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST healthz = %d, want 405", w.Code)
	}

	// The public handler does not expose the host-side health endpoint.
	w = httptest.NewRecorder()
	rl.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("public healthz = %d, want 404", w.Code)
	}
}
