package relay

import "testing"

func fakeEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := LoadConfig(fakeEnv(map[string]string{
		"RELAY_MASTER_SECRET": "6d61737465722d736563726574000000000000000000000000000000000000ff",
		"RELAY_PUBLIC_URL":    "https://cloudprint.wcpos.com",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":8443" || cfg.HealthAddr != "127.0.0.1:8080" {
		t.Errorf("bad listen defaults: %q %q", cfg.ListenAddr, cfg.HealthAddr)
	}
	if cfg.Mode != "transparent" {
		t.Errorf("default mode must be transparent (Phase A rollout), got %q", cfg.Mode)
	}
	if cfg.HeartbeatInterval.Seconds() != 60 || cfg.PendingTTL.Seconds() != 120 {
		t.Errorf("bad adaptive defaults: %v %v", cfg.HeartbeatInterval, cfg.PendingTTL)
	}
	if len(cfg.MasterSecret) != 32 {
		t.Errorf("master secret must decode to 32 bytes, got %d", len(cfg.MasterSecret))
	}
}

func TestLoadConfigRejectsMissingOrShortSecret(t *testing.T) {
	if _, err := LoadConfig(fakeEnv(map[string]string{"RELAY_PUBLIC_URL": "https://r.example"})); err == nil {
		t.Fatal("want error for missing RELAY_MASTER_SECRET")
	}
	if _, err := LoadConfig(fakeEnv(map[string]string{
		"RELAY_MASTER_SECRET": "abcd", "RELAY_PUBLIC_URL": "https://r.example",
	})); err == nil {
		t.Fatal("want error for short secret")
	}
}
