package relay

import (
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
		{"http://example.com", "", true},          // https only
		{"https://example.com/wp-json", "", true}, // no paths
		{"https://user:pw@example.com", "", true}, // no userinfo
		{"https://example.com?x=1", "", true},     // no query
		{"", "", true},
	}
	for _, c := range cases {
		got, err := CanonicalOrigin(c.in)
		if c.wantErr != (err != nil) || got != c.want {
			t.Errorf("CanonicalOrigin(%q) = %q, %v; want %q, err=%v", c.in, got, err, c.want, c.wantErr)
		}
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
