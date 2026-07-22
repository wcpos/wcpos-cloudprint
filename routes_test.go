package relay

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRoutesWiring(t *testing.T) {
	_, ts := newFakeOrigin(t)
	rl := testRelay(t, ts.Client())
	h := rl.Handler()

	// healthz
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != 200 {
		t.Fatalf("healthz = %d", w.Code)
	}
	// unknown paths 404 — nothing else is proxyable
	for _, path := range []string{"/", "/p/abc/other-endpoint", "/wp-json/wcpos/v1/print-jobs/cloudprnt"} {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != 404 {
			t.Errorf("%s = %d, want 404", path, w.Code)
		}
	}
}
