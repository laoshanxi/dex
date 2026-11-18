package authflow

import (
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"
)

// TestSAMLRelayPageScriptHashPinned: the auto-post page's script must stay
// pinned by hash in its CSP. Editing the page without the policy breaks the
// page in every browser, so this fails first.
func TestSAMLRelayPageScriptHashPinned(t *testing.T) {
	re := regexp.MustCompile(`(?s)<script>(.*?)</script>`)
	m := re.FindStringSubmatch(samlRelayPage)
	if m == nil {
		t.Fatal("samlRelayPage has no script to pin")
	}
	sum := sha256.Sum256([]byte(m[1]))
	hash := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	if !strings.Contains(samlRelayContentSecurityPolicy, hash) {
		t.Errorf("script hash %s is missing from samlRelayContentSecurityPolicy", hash)
	}
}
