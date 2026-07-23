package relay

import (
	"log"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// ptRedact masks the printer's pt token wherever it appears in a logged query
// string, so access logs never carry the end-to-end printer credential (D5).
var ptRedact = regexp.MustCompile(`(pt=)[^&]*`)

// pathCreds matches path-credential printer URLs (/p/{key}/{printer}/{token}/…)
// so the token segment can be masked and the printer id logged. The mux clones
// the request before handlers run, so PathValue is not visible in middleware;
// legacy two-segment paths (/p/{key}/cloudprnt) carry no token and never match.
var pathCreds = regexp.MustCompile(`^(/p/[^/]+/([^/]+)/)[^/]+(/.+)$`)

// statusRecorder captures the response status and byte count for access logging.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// LogRequests logs one metadata line per request — method, path, query (with
// the pt token redacted), the parsed printer_id, status, bytes, and duration.
// Never logs request/response bodies or the pt token. /healthz is skipped so
// uptime polling doesn't drown the log. Disk use is bounded by the container's
// json-file log rotation (see docker-compose.yml), not here.
func LogRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w}
		start := time.Now()
		next.ServeHTTP(rec, r)
		query := r.URL.RawQuery
		path := r.URL.EscapedPath()
		printer := r.URL.Query().Get("printer_id")
		if m := pathCreds.FindStringSubmatch(path); m != nil {
			path = m[1] + "<redacted>" + m[3]
			printer = m[2]
			if decoded, err := url.QueryUnescape(query); err == nil {
				query = decoded
			} else {
				query = ""
			}
		}
		query = ptRedact.ReplaceAllString(query, "${1}<redacted>")
		log.Printf(
			"req method=%s path=%s query=%q printer_id=%q status=%d bytes=%d dur=%s",
			r.Method, path, query, printer,
			rec.status, rec.bytes, time.Since(start).Round(time.Millisecond),
		)
	})
}
