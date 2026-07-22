package relay

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCanonicalOrigin(t *testing.T) {
	cases := []struct {
		in, want string
		wantErr  bool
	}{
		{"https://Example.COM/", "https://example.com", false},
		{"https://example.com", "https://example.com", false},
		{"https://example.com:8443", "https://example.com:8443", false},
		{"https://Example.com/Shop/", "https://example.com/Shop", false},
		{"https://example.com/shop", "https://example.com/shop", false},
		{"http://example.com", "", true},          // https only
		{"https://user:pw@example.com", "", true}, // no userinfo
		{"https://example.com?x=1", "", true},     // no query
		{"https://example.com/#fragment", "", true},
		{"", "", true},
	}
	for _, c := range cases {
		got, err := CanonicalOrigin(c.in)
		if c.wantErr != (err != nil) || got != c.want {
			t.Errorf("CanonicalOrigin(%q) = %q, %v; want %q, err=%v", c.in, got, err, c.want, c.wantErr)
		}
	}
}

func TestStorePutFailureLeavesMapUnchanged(t *testing.T) {
	s := &Store{path: filepath.Join(t.TempDir(), "missing", "sites.json"), sites: map[string]Site{
		"old": {Key: "old", Origin: "https://old.example"},
	}}
	if err := s.Put(Site{Key: "new", Origin: "https://new.example"}); err == nil {
		t.Fatal("Put must fail when the destination directory is absent")
	}
	if _, ok := s.Get("new"); ok {
		t.Fatal("failed Put must not mutate the in-memory map")
	}
	if _, ok := s.Get("old"); !ok {
		t.Fatal("failed Put must preserve existing sites")
	}
}

func TestStoreCapsNewSitesButAllowsUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	s := &Store{path: path, sites: make(map[string]Site, 5000)}
	for i := 0; i < 5000; i++ {
		key := string(rune(i + 1))
		s.sites[key] = Site{Key: key}
	}
	if err := s.Put(Site{Key: "new"}); err == nil {
		t.Fatal("new site beyond cap must fail")
	}
	if err := s.Put(Site{Key: string(rune(1)), Origin: "https://updated.example"}); err != nil {
		t.Fatalf("existing site update at cap failed: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("updated store was not persisted: %v", err)
	}
}

func TestSiteKeyDeterministicAndSecretDependent(t *testing.T) {
	m1 := []byte("0123456789abcdef0123456789abcdef")
	m2 := []byte("fedcba9876543210fedcba9876543210")
	a := SiteKey(m1, "https://example.com")
	if a != SiteKey(m1, "https://example.com") {
		t.Error("key must be deterministic")
	}
	if len(a) != 32 {
		t.Errorf("key must be 32 hex chars, got %d", len(a))
	}
	if a == SiteKey(m2, "https://example.com") || a == SiteKey(m1, "https://other.com") {
		t.Error("key must depend on both secret and origin")
	}
}

func TestStoreRoundTripAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sites.json")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	site := Site{Key: "abc123", Origin: "https://example.com", HintSecret: "deadbeef", CreatedAt: time.Now().UTC()}
	if err := s.Put(site); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.Get("abc123"); !ok || got.Origin != site.Origin {
		t.Fatalf("Get after Put = %+v, %v", got, ok)
	}
	s2, err := OpenStore(path) // survives restart
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := s2.Get("abc123"); !ok || got.HintSecret != "deadbeef" {
		t.Fatalf("Get after reload = %+v, %v", got, ok)
	}
	if _, ok := s2.Get("missing"); ok {
		t.Error("unknown key must miss")
	}
}
