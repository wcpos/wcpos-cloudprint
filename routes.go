package relay

import "net/http"

func (rl *Relay) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("POST /api/register", rl.handleRegister)
	mux.HandleFunc("POST /api/hint/{key}", rl.handleHint)
	mux.HandleFunc("GET /api/status/{key}", rl.handleStatus)
	mux.HandleFunc("/p/{key}/cloudprnt", rl.handleCloudPRNT)
	mux.HandleFunc("/p/{key}/epson-sdp", rl.handleSDP)
	// Path-credential form: Star printers URL-encode the configured query
	// string (& -> %26), destroying printer_id/pt as parameters — but they
	// transmit the path verbatim, so identity rides in the path instead.
	mux.HandleFunc("/p/{key}/{printer}/{token}/cloudprnt", rl.handleCloudPRNT)
	mux.HandleFunc("/p/{key}/{printer}/{token}/epson-sdp", rl.handleSDP)
	return mux
}
