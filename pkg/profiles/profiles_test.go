package profiles

import (
	"testing"
	"time"

	"github.com/NotChaosuu/spoofprint/pkg/model"
)

const (
	chromeJA4_16ext = "t13d1516h2_8daaf6152771_d8a2da3f94cd"
	chromeJA4_17ext = "t13d1517h2_8daaf6152771_b6f405a00624"
	edgeJA4         = "t13d1516h2_8daaf6152771_806a8c22fdea"
	firefoxJA4      = "t13d1617h2_86a278354501_3cbfd9057e0d"
)

func TestFamilyFromJA4_ChromiumBothExtCounts(t *testing.T) {
	for _, ja4 := range []string{chromeJA4_16ext, chromeJA4_17ext, edgeJA4} {
		if got := FamilyFromJA4(ja4); got != model.Chrome {
			t.Errorf("FamilyFromJA4(%q) = %q, want chrome (cipher hash is Chromium)", ja4, got)
		}
	}
}

func TestFamilyFromJA4_Chrome17ExtIsNotSafari(t *testing.T) {
	if got := FamilyFromJA4(chromeJA4_17ext); got == model.Safari {
		t.Fatal("17-ext Chrome must not resolve to Safari via its shared part-A prefix")
	}
}

func TestFamilyFromJA4_Firefox(t *testing.T) {
	if got := FamilyFromJA4(firefoxJA4); got != model.Firefox {
		t.Errorf("FamilyFromJA4(firefox) = %q, want firefox", got)
	}
}

func TestFamilyFromJA4_UnknownCipherHash(t *testing.T) {
	if got := FamilyFromJA4("t13d1516h2_ffffffffffff_000000000000"); got != model.Unknown {
		t.Errorf("unknown cipher hash should be Unknown, got %q", got)
	}
	if got := FamilyFromJA4("not-a-ja4"); got != model.Unknown {
		t.Errorf("malformed JA4 should be Unknown, got %q", got)
	}
}

func TestJA4CipherHash(t *testing.T) {
	if got := JA4CipherHash(chromeJA4_16ext); got != "8daaf6152771" {
		t.Errorf("cipher hash = %q, want 8daaf6152771", got)
	}
	if got := JA4CipherHash("garbage"); got != "" {
		t.Errorf("malformed JA4 cipher hash = %q, want empty", got)
	}
}

func TestClaimedBrowser_EdgeBeforeChrome(t *testing.T) {
	edgeUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0"
	if got := ClaimedBrowser(edgeUA); got != model.Edge {
		t.Errorf("Edge UA resolved to %q, want edge", got)
	}

	chromeUA := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
	if got := ClaimedBrowser(chromeUA); got != model.Chrome {
		t.Errorf("Chrome UA resolved to %q, want chrome", got)
	}
}

func TestAllProfilesHaveCipherHash(t *testing.T) {
	for _, p := range Browsers() {
		if p.JA4CipherHash == "" {
			t.Errorf("%s profile is missing JA4CipherHash", p.Name)
		}
	}
}

// Captured profiles must carry a parseable capture date; Safari is deliberately
// left uncaptured (assumed) and must NOT claim one.
func TestProfileProvenance(t *testing.T) {
	defer resetProfiles()
	for _, p := range Browsers() {
		switch p.Family {
		case model.Safari:
			if p.CapturedOn != "" {
				t.Errorf("Safari values are assumed — it must not claim a capture date, got %q", p.CapturedOn)
			}
		default:
			if _, err := time.Parse("2006-01-02", p.CapturedOn); err != nil {
				t.Errorf("%s profile has no/invalid captured_on %q: %v", p.Name, p.CapturedOn, err)
			}
		}
	}
}

// A runtime override replaces the built-in of the same family everywhere the
// scorer reads it — the whole point of decoupling freshness from the binary.
func TestLoadProfilesOverridesBuiltin(t *testing.T) {
	defer resetProfiles()
	json := `[{"name":"Chrome","family":"chrome","ja4_prefix":"t13d9999h2","ja4_cipher_hash":"deadbeefcafe","akamai_h2":"1:99|1|0|m,a,s,p","pseudo_order":"m,a,s,p","expects_mlkem":true,"expects_alps":true,"expects_grease":true,"ua_tokens":["Chrome/"],"captured_on":"2026-07-30","versions":"Chrome 152"}]`
	n, err := LoadProfiles([]byte(json))
	if err != nil || n != 1 {
		t.Fatalf("LoadProfiles = %d, %v; want 1, nil", n, err)
	}
	p, ok := ByFamily(model.Chrome)
	if !ok || p.JA4CipherHash != "deadbeefcafe" {
		t.Fatalf("override not applied: %+v (ok=%v)", p, ok)
	}
	// A fresh capture-hash must now resolve to Chrome via the overridden profile.
	if got := FamilyFromJA4("t13d9999h2_deadbeefcafe_000000000000"); got != model.Chrome {
		t.Errorf("FamilyFromJA4 after override = %q, want chrome", got)
	}
}

func TestLoadProfilesRejectsIncomplete(t *testing.T) {
	defer resetProfiles()
	if _, err := LoadProfiles([]byte(`[{"name":"X","family":"chrome"}]`)); err == nil {
		t.Error("a profile without ja4_cipher_hash must be rejected, not silently applied")
	}
	if _, err := LoadProfiles([]byte(`not json`)); err == nil {
		t.Error("invalid JSON must error")
	}
}

func TestStaleProfilesFlagsOldAndAssumed(t *testing.T) {
	defer resetProfiles()
	// A year out from the 2026-07-29 captures: the three captured profiles are
	// stale, and Safari (assumed) is always flagged.
	now, _ := time.Parse("2006-01-02", "2027-08-01")
	warns := StaleProfiles(now, 180*24*time.Hour)
	if len(warns) != 4 {
		t.Errorf("expected all 4 profiles flagged (3 stale + Safari assumed), got %d: %v", len(warns), warns)
	}
	// Fresh: as of the day after capture, only Safari (assumed) is flagged.
	fresh, _ := time.Parse("2006-01-02", "2026-07-30")
	if warns := StaleProfiles(fresh, 180*24*time.Hour); len(warns) != 1 {
		t.Errorf("fresh captures should leave only Safari flagged, got %d: %v", len(warns), warns)
	}
}
