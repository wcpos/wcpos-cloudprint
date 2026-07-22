package relay

import "net/http"

func (rl *Relay) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/register", rl.handleRegister)
	mux.HandleFunc("POST /api/hint/{key}", rl.handleHint)
	mux.HandleFunc("GET /api/status/{key}", rl.handleStatus)
	mux.HandleFunc("/p/{key}/cloudprnt", rl.handleCloudPRNT)
	mux.HandleFunc("/p/{key}/epson-sdp", rl.handleSDP)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}
