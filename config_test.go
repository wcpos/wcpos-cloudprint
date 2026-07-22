package relay

import "testing"

func TestParseMasterSecret(t *testing.T) {
	secret, err := ParseMasterSecret("6d61737465722d736563726574000000000000000000000000000000000000ff")
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 32 {
		t.Errorf("master secret must decode to 32 bytes, got %d", len(secret))
	}
	for name, bad := range map[string]string{
		"missing":   "",
		"too short": "abcd",
		"not hex":   "zz61737465722d736563726574000000000000000000000000000000000000ff",
	} {
		if _, err := ParseMasterSecret(bad); err == nil {
			t.Errorf("%s secret must be rejected", name)
		}
	}
}
