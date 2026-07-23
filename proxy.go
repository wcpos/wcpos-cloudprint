package relay

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	maxPrinterBody = 64 << 10 // printer->relay request bodies (poll status JSON / SDP posts)
	maxPollBody    = 8 << 10  // origin poll responses are tiny JSON; buffered for jobReady inspection
	maxPayloadBody = 10 << 20 // origin GET payloads (raster receipts) are streamed up to this
	// sdpAck must byte-match Print_Jobs_Controller::epson_sdp()'s ack.
	sdpAck     = `<response success="true" code="" status=""/>`
	sdpXMLType = "text/xml; charset=utf-8"
	// relayUA identifies the relay honestly to origins and their security
	// layers (D9): stable, documented, allowlistable. Never a browser UA.
	relayUA = "WCPOS-CloudPrint/1.0 (+https://wcpos.com/cloudprint)"
)

func localNoJob(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"jobReady":false}`))
}

func localSDPAck(w http.ResponseWriter) {
	w.Header().Set("Content-Type", sdpXMLType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(sdpAck))
}

// printerCredentials resolves a request's printer identity and the query
// string to forward to the origin. Path-credential routes rebuild the exact
// `wcpos=1&printer_id=…&pt=…` query the plugin expects (the printer never
// transmitted one it didn't mangle); legacy routes pass the printer's query
// through untouched.
func printerCredentials(r *http.Request) (printer, forwardQuery string) {
	if p := r.PathValue("printer"); p != "" {
		q := url.Values{
			"wcpos":      {"1"},
			"printer_id": {p},
			"pt":         {r.PathValue("token")},
		}
		return p, q.Encode()
	}
	return r.URL.Query().Get("printer_id"), r.URL.RawQuery
}

// originRequest re-issues the printer's request against the registered
// origin. Only the resolved query string, method, body and Content-Type
// survive; no other client headers cross the boundary in either direction.
func (rl *Relay) originRequest(r *http.Request, site Site, endpoint, forwardQuery string, body io.Reader) (*http.Response, error) {
	u := site.Origin + "/wp-json/wcpos/v1/print-jobs/" + endpoint
	if forwardQuery != "" {
		u += "?" + forwardQuery
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, u, body)
	if err != nil {
		return nil, err
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("User-Agent", relayUA)
	req.Header.Set("X-WCPOS", "1")
	if pua := r.UserAgent(); pua != "" {
		req.Header.Set("X-WCPOS-Printer-Agent", pua)
	}
	return rl.Origin.Do(req)
}

// classifyBlock decides whether an origin response is the WCPOS plugin
// talking or a security layer intercepting us. The plugin's own answers —
// including its 4xx errors — carry "wcpos_…" error codes, so they never
// count as blocks. Legitimate SDP XML (`<?xml`, `<response`) is not HTML.
// Returns "" for legitimate responses, else a short signal for /api/status.
func classifyBlock(resp *http.Response, body []byte) string {
	if bytes.Contains(body, []byte(`"wcpos_`)) {
		return ""
	}
	if m := resp.Header.Get("cf-mitigated"); m != "" {
		return "cloudflare-" + m
	}
	switch resp.StatusCode {
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusGatewayTimeout,
		http.StatusUnauthorized, http.StatusForbidden:
		return "http-" + strconv.Itoa(resp.StatusCode)
	case http.StatusTooManyRequests:
		return "http-429"
	case http.StatusServiceUnavailable:
		return "http-503"
	}
	trimmed := bytes.TrimSpace(body)
	prefix := trimmed
	if len(prefix) > 16 {
		prefix = prefix[:16]
	}
	prefix = bytes.ToLower(prefix)
	if bytes.HasPrefix(prefix, []byte("<!doctype")) || bytes.HasPrefix(prefix, []byte("<html")) {
		return "html-instead-of-api-response"
	}
	return ""
}

// handleCloudPRNT serves /p/{key}/cloudprnt — the Star CloudPRNT triplet.
func (rl *Relay) handleCloudPRNT(w http.ResponseWriter, r *http.Request) {
	site, ok := rl.Store.Get(r.PathValue("key"))
	if !ok {
		jsonError(w, http.StatusNotFound, "unknown site")
		return
	}
	printer, forwardQuery := printerCredentials(r)
	now := rl.Now()
	rl.State.Seen(site.Key, printer, now)

	switch r.Method {
	case http.MethodPost: // poll
		body, err := io.ReadAll(io.LimitReader(r.Body, maxPrinterBody))
		if err != nil {
			jsonError(w, http.StatusBadRequest, "unreadable body")
			return
		}
		if !rl.State.ShouldForward(site.Key, printer, now, HeartbeatInterval, PendingTTL) {
			localNoJob(w)
			return
		}
		if blocked, _ := rl.Health.Blocked(site.Key, now); blocked {
			localNoJob(w) // breaker open: don't feed the WAF
			return
		}
		if !rl.FwdLim.Allow("fwd|" + site.Key) {
			localNoJob(w)
			return
		}
		resp, err := rl.originRequest(r, site, "cloudprnt", forwardQuery, bytes.NewReader(body))
		if err != nil {
			rl.State.NoteForward(site.Key, printer, now)
			localNoJob(w) // origin down: stay calm, heartbeat retries later
			return
		}
		defer func() { _ = resp.Body.Close() }()
		rl.State.NoteForward(site.Key, printer, now)
		pollBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxPollBody))
		if sig := classifyBlock(resp, pollBody); sig != "" {
			rl.Health.NoteBlock(site.Key, sig, now)
			localNoJob(w) // never forward a challenge page to a printer
			return
		}
		rl.Health.NoteOK(site.Key, now)
		if resp.StatusCode == http.StatusOK && !bytes.Contains(pollBody, []byte(`"jobReady":true`)) {
			rl.State.ClearPending(site.Key, printer) // queue drained
		}
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", strconv.Itoa(len(pollBody)))
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(pollBody)

	case http.MethodGet, http.MethodDelete: // fetch payload / confirm result
		if blocked, _ := rl.Health.Blocked(site.Key, now); blocked {
			jsonError(w, http.StatusBadGateway, "origin blocked the relay")
			return
		}
		if !rl.FetchLim.Allow("fetch|" + site.Key) {
			jsonError(w, http.StatusServiceUnavailable, "over rate limit")
			return
		}
		resp, err := rl.originRequest(r, site, "cloudprnt", forwardQuery, nil)
		if err != nil {
			jsonError(w, http.StatusBadGateway, "origin unreachable")
			return
		}
		defer func() { _ = resp.Body.Close() }()
		head := make([]byte, 512)
		n, _ := io.ReadFull(resp.Body, head)
		if sig := classifyBlock(resp, head[:n]); sig != "" {
			rl.Health.NoteBlock(site.Key, sig, now)
			jsonError(w, http.StatusBadGateway, "origin blocked the relay")
			return
		}
		rl.Health.NoteOK(site.Key, now)
		if ct := resp.Header.Get("Content-Type"); ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		if r.Method == http.MethodGet {
			if resp.ContentLength >= 0 && resp.ContentLength <= maxPayloadBody {
				w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(head[:n])
		_, _ = io.Copy(w, io.LimitReader(resp.Body, int64(maxPayloadBody-n)))

	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleSDP serves /p/{key}/epson-sdp. SDP multiplexes polls and print-result
// reports over POST; results skip only adaptive polling gates.
func (rl *Relay) handleSDP(w http.ResponseWriter, r *http.Request) {
	site, ok := rl.Store.Get(r.PathValue("key"))
	if !ok {
		jsonError(w, http.StatusNotFound, "unknown site")
		return
	}
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	printer, forwardQuery := printerCredentials(r)
	now := rl.Now()
	rl.State.Seen(site.Key, printer, now)

	body, err := io.ReadAll(io.LimitReader(r.Body, maxPrinterBody))
	if err != nil {
		localSDPAck(w)
		return
	}
	resultBody := body
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/x-www-form-urlencoded") {
		if decoded, decodeErr := url.QueryUnescape(string(body)); decodeErr == nil {
			resultBody = []byte(decoded)
		}
	}
	isResult := bytes.Contains(resultBody, []byte("success="))
	if !isResult && !rl.State.ShouldForward(site.Key, printer, now, HeartbeatInterval, PendingTTL) {
		localSDPAck(w)
		return
	}
	if blocked, _ := rl.Health.Blocked(site.Key, now); blocked {
		localSDPAck(w)
		return
	}
	if !rl.FwdLim.Allow("fwd|" + site.Key) {
		localSDPAck(w)
		return
	}
	resp, err := rl.originRequest(r, site, "epson-sdp", forwardQuery, bytes.NewReader(body))
	if err != nil {
		localSDPAck(w) // origin down: ack so the printer keeps cycling
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if !isResult {
		rl.State.NoteForward(site.Key, printer, now)
	}
	// An SDP poll response carries the ePOS-Print job payload (may include
	// images), not a tiny status blob — buffer up to the full payload cap.
	sdpBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxPayloadBody))
	if sig := classifyBlock(resp, sdpBody); sig != "" {
		rl.Health.NoteBlock(site.Key, sig, now)
		localSDPAck(w)
		return
	}
	rl.Health.NoteOK(site.Key, now)
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(sdpBody)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(sdpBody)
}
