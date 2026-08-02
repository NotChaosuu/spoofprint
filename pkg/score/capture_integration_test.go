package score

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/NotChaosuu/spoofprint/pkg/model"
)

func TestRealCapturesAreNotSpoofed(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "captures")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Skipf("no captures dir (%v) — run scripts/capture.ps1 to generate", err)
	}

	scored := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(root, e.Name(), "*.json"))
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			var fp model.Fingerprint
			if err := json.Unmarshal(data, &fp); err != nil {
				t.Fatalf("unmarshal %s: %v", f, err)
			}
			scored++
			v := Score(fp)

			if v.Label == "spoofed" {
				t.Errorf("%s: REAL browser scored spoofed (%d): %+v", f, v.SpoofScore, v.Violations)
			}

			if fp.UserAgent != "" && v.ClaimedBrowser != model.Unknown && v.Label != "consistent" {
				t.Errorf("%s: real %s scored %s/%d, want consistent: %+v",
					f, v.ClaimedBrowser, v.Label, v.SpoofScore, v.Violations)
			}
		}
	}
	if scored == 0 {
		t.Skip("no capture files present")
	}
	t.Logf("scored %d real browser captures — none spoofed", scored)
}
