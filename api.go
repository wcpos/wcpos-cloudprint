package relay

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"
)

// handleRegister implements POST /api/register. The relay proves the site
// consents (and actually runs WCPOS) by fetching the plugin's verification
// endpoint and matching the caller-supplied token. See Appendix A.
func (rl *Relay) handleRegister(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !rl.RegLim.Allow("reg|" + ip) {
		jsonError(w, http.StatusTooManyRequests, "too many registration attempts")
		return
	}
	var in struct {
		SiteURL     string `json:"site_url"`
		VerifyToken string `json:"verify_token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&in); err != nil || in.VerifyToken == "" {
		jsonError(w, http.StatusBadRequest, "site_url and verify_token are required")
		return
	}
	origin, err := CanonicalOrigin(in.SiteURL)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "invalid site_url: "+err.Error())
		return
	}

	resp, err := rl.Origin.Get(origin + "/wp-json/wcpos/v1/print-jobs/relay-verification")
	if err != nil {
		jsonError(w, http.StatusBadGateway, "could not reach site verification endpoint")
		return
	}
	defer resp.Body.Close()
	var check struct {
		Token string `json:"token"`
	}
	if resp.StatusCode != http.StatusOK ||
		json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&check) != nil {
		jsonError(w, http.StatusBadGateway, "site verification endpoint did not answer correctly")
		return
	}
	if subtle.ConstantTimeCompare([]byte(check.Token), []byte(in.VerifyToken)) != 1 {
		jsonError(w, http.StatusForbidden, "verification token mismatch")
		return
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		jsonError(w, http.StatusInternalServerError, "entropy unavailable")
		return
	}
	site := Site{
		Key:        SiteKey(rl.Cfg.MasterSecret, origin),
		Origin:     origin,
		HintSecret: hex.EncodeToString(secret),
		CreatedAt:  rl.Now().UTC(),
	}
	if err := rl.Store.Put(site); err != nil {
		jsonError(w, http.StatusInternalServerError, "could not persist registration")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{
		"site_key":         site.Key,
		"hint_secret":      site.HintSecret,
		"printer_base_url": rl.Cfg.PublicBaseURL + "/p/" + site.Key,
	})
}

// authedSite resolves {key} and checks the HMAC headers over payload.
func (rl *Relay) authedSite(w http.ResponseWriter, r *http.Request, payload []byte) (Site, bool) {
	site, ok := rl.Store.Get(r.PathValue("key"))
	if !ok {
		jsonError(w, http.StatusNotFound, "unknown site")
		return Site{}, false
	}
	secret, err := hexDecode(site.HintSecret)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "corrupt site record")
		return Site{}, false
	}
	ts := r.Header.Get("X-Relay-Timestamp")
	sig := r.Header.Get("X-Relay-Signature")
	if VerifySignature(secret, ts, sig, payload, rl.Now(), 5*time.Minute) != nil {
		jsonError(w, http.StatusUnauthorized, "invalid signature")
		return Site{}, false
	}
	return site, true
}

// handleHint implements POST /api/hint/{key}: the plugin's job-enqueued push.
func (rl *Relay) handleHint(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<10))
	if err != nil {
		jsonError(w, http.StatusBadRequest, "unreadable body")
		return
	}
	site, ok := rl.authedSite(w, r, body)
	if !ok {
		return
	}
	var in struct {
		PrinterID string `json:"printer_id"`
	}
	if json.Unmarshal(body, &in) != nil || in.PrinterID == "" {
		jsonError(w, http.StatusBadRequest, "printer_id is required")
		return
	}
	rl.State.Hint(site.Key, in.PrinterID, rl.Now())
	w.WriteHeader(http.StatusNoContent)
}

// handleStatus implements GET /api/status/{key}?printer_id=… — signature is
// over the printer_id string. Lets the plugin show "printer polled Ns ago".
func (rl *Relay) handleStatus(w http.ResponseWriter, r *http.Request) {
	printer := r.URL.Query().Get("printer_id")
	site, ok := rl.authedSite(w, r, []byte(printer))
	if !ok {
		return
	}
	state, signal := rl.Health.Status(site.Key, rl.Now())
	out := map[string]any{
		"printer_id":            printer,
		"last_seen_seconds_ago": nil,
		"origin_status":         state,
		"origin_block_signal":   signal,
	}
	if seen, ok := rl.State.LastSeen(site.Key, printer); ok {
		out["last_seen_seconds_ago"] = int64(rl.Now().Sub(seen).Seconds())
	}
	writeJSON(w, http.StatusOK, out)
}
