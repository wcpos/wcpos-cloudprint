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

// CanonicalOrigin reduces a user-supplied site URL to "https://host[:port]".
// Anything beyond scheme+host is rejected so the stored origin can never
// smuggle a path, query, or credentials into forwarded requests.
func CanonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if u.Scheme != "https" {
		return "", errors.New("origin must use https")
	}
	if u.Host == "" {
		return "", errors.New("origin must include a host")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", errors.New("origin must be scheme and host only")
	}
	return "https://" + strings.ToLower(u.Host), nil
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
	s.sites[site.Key] = site
	data, err := json.MarshalIndent(s.sites, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) Get(key string) (Site, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	site, ok := s.sites[key]
	return site, ok
}
