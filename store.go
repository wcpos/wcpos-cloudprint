package relay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Site is one registered WCPOS installation the relay may forward to.
type Site struct {
	Key        string    `json:"key"`
	Origin     string    `json:"origin"`
	HintSecret string    `json:"hint_secret"` // hex-encoded 32 bytes
	CreatedAt  time.Time `json:"created_at"`
}

// CanonicalOrigin reduces a user-supplied site URL to an HTTPS host and
// optional WordPress installation path.
func CanonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", errors.New("origin must use https")
	}
	if u.Host == "" {
		return "", errors.New("origin must include a host")
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", errors.New("origin must not include query, fragment, or userinfo")
	}
	return "https://" + strings.ToLower(u.Host) + strings.TrimRight(u.EscapedPath(), "/"), nil
}

// SiteKey derives the stable public identifier for an origin. Deterministic
// so a lost registry can be rebuilt by re-registration without breaking
// printer URLs already configured on devices in the field.
func SiteKey(master []byte, origin string) string {
	mac := hmac.New(sha256.New, master)
	mac.Write([]byte(origin))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

// Store is a mutex-guarded map persisted to a JSON file with atomic writes.
// Registrations are rare and sites number in the hundreds; a database would
// be pure overhead.
type Store struct {
	mu    sync.RWMutex
	path  string
	sites map[string]Site
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, sites: map[string]Site{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &s.sites); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Put(site Site) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := make(map[string]Site, len(s.sites)+1)
	for key, existing := range s.sites {
		next[key] = existing
	}
	next[site.Key] = site
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.sites = next
	return nil
}

func (s *Store) Get(key string) (Site, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	site, ok := s.sites[key]
	return site, ok
}
