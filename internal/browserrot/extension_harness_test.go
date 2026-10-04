package browserrot

import (
	"os/exec"
	"testing"
)

// TestExtensionJS_backgroundHarness runs extension/background.js under a stubbed chrome API
// (testdata/background_harness.js) to prove the session is PINNED to one tab: DOM commands
// (including the secret fills) never follow focus to another tab, a closed pinned tab is an
// error rather than a fallback, and a fill is refused off the goto origin. Skipped when node
// is not on PATH.
func TestExtensionJS_backgroundHarness(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH; background.js harness skipped")
	}
	out, err := exec.Command(node, "testdata/background_harness.js", "extension/background.js").CombinedOutput()
	t.Logf("\n%s", out)
	if err != nil {
		t.Fatalf("background.js harness failed: %v", err)
	}
}
