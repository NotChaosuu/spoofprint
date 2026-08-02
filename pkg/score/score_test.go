package score

import (
	"testing"

	"github.com/NotChaosuu/spoofprint/pkg/model"
	"github.com/NotChaosuu/spoofprint/pkg/profiles"
)

func chromeUA(v string) string {
	return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" + v + ".0.0.0 Safari/537.36"
}

func realChrome() model.Fingerprint {
	return model.Fingerprint{
		JA4:           "t13d1516h2_8daaf6152771_02713d6af862",
		AkamaiH2:      "1:65536;2:0;4:6291456;6:262144|15663105|1:1:0:256|m,a,s,p",
		UserAgent:     chromeUA("151"),
		HTTPVersion:   "2",
		PseudoOrder:   "m,a,s,p",
		GREASEPresent: true,
		HasMLKEM:      true,
		HasALPS:       true,
		SecCHUA:       `"Google Chrome";v="151", "Chromium";v="151", "Not(A:Brand";v="24"`,
	}
}

func realFirefox() model.Fingerprint {
	return model.Fingerprint{
		JA4:           "t13d1617h2_86a278354501_3cbfd9057e0d",
		AkamaiH2:      "1:65536;2:0;4:131072;5:16384|12517377|3:0:0:42|m,p,a,s",
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; rv:153.0) Gecko/20100101 Firefox/153.0",
		HTTPVersion:   "2",
		PseudoOrder:   "m,p,a,s",
		GREASEPresent: false,
		HasMLKEM:      true,
	}
}

func realSafari() model.Fingerprint {
	return model.Fingerprint{
		JA4:           "t13d1517h2_a09f3c656075_14788d8d241b",
		AkamaiH2:      "2:0;4:4194304;3:100|10485760|0|m,s,p,a",
		UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
		HTTPVersion:   "2",
		PseudoOrder:   "m,s,p,a",
		GREASEPresent: true,
		HasMLKEM:      true,
		HasALPS:       false,
	}
}

func realEdge() model.Fingerprint {
	fp := realChrome()
	fp.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36 Edg/150.0.0.0"
	fp.SecCHUA = `"Microsoft Edge";v="150", "Chromium";v="150", "Not(A:Brand";v="24"`
	return fp
}

func TestRealBrowsersAreConsistent(t *testing.T) {
	cases := map[string]model.Fingerprint{
		"chrome":  realChrome(),
		"firefox": realFirefox(),
		"safari":  realSafari(),
		"edge":    realEdge(),
	}
	for name, fp := range cases {
		v := Score(fp)
		if v.Label != "consistent" || v.SpoofScore != 0 {
			t.Errorf("%s: expected consistent/0, got %s/%d with violations %+v", name, v.Label, v.SpoofScore, v.Violations)
		}
	}
}

func TestCurlClaimingChromeIsSpoofed(t *testing.T) {
	fp := model.Fingerprint{
		JA4:           "t13d4907h2_abcabcabcabc_defdefdefdef",
		UserAgent:     chromeUA("151"),
		HTTPVersion:   "2",
		PseudoOrder:   "m,s,a,p",
		GREASEPresent: false,
		HasMLKEM:      false,
	}
	v := Score(fp)
	if v.Label != "spoofed" {
		t.Errorf("curl-claiming-Chrome should be spoofed, got %s/%d", v.Label, v.SpoofScore)
	}
	if !hasRule(v, "bot-fingerprint") {
		t.Error("expected the curl bot-fingerprint rule to fire")
	}
}

func TestGoHTTPClaimingChromeIsSpoofed(t *testing.T) {
	fp := model.Fingerprint{
		UserAgent:     chromeUA("151"),
		HTTPVersion:   "2",
		PseudoOrder:   "a,m,p,s",
		GREASEPresent: false,
	}
	v := Score(fp)
	if v.Label != "spoofed" {
		t.Errorf("Go-http claiming Chrome should be spoofed, got %s/%d", v.Label, v.SpoofScore)
	}
	if !hasRule(v, "bot-fingerprint") {
		t.Errorf("real Go pseudo-order a,m,p,s must trip bot-fingerprint, got %+v", v.Violations)
	}
}

func TestRealFirefoxH2IsConsistent(t *testing.T) {
	fp := model.Fingerprint{
		JA4:           "t13d1617h2_86a278354501_3cbfd9057e0d",
		AkamaiH2:      "1:65536;2:0;4:131072;5:16384|12517377|3:0:0:42|m,p,a,s",
		UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0",
		HTTPVersion:   "2",
		PseudoOrder:   "m,p,a,s",
		GREASEPresent: false,
		HasMLKEM:      true,
		HasALPS:       false,
	}
	v := Score(fp)
	if v.Label != "consistent" || v.SpoofScore != 0 {
		t.Fatalf("real Firefox 153 must be consistent/0, got %s/%d %+v", v.Label, v.SpoofScore, v.Violations)
	}
}

func TestH2ExtraSettingToleratedNoSpoof(t *testing.T) {
	fp := realChrome()
	fp.AkamaiH2 = "1:65536;2:0;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p"
	if v := Score(fp); v.Label == "spoofed" {
		t.Errorf("an extra SETTINGS entry must not force spoofed (drift-resilience), got %s/%d %+v", v.Label, v.SpoofScore, v.Violations)
	}
}

func TestH2WrongSharedSettingIsMediumNotSpoofedAlone(t *testing.T) {
	fp := realChrome()
	fp.AkamaiH2 = "1:65536;2:0;4:9999999;6:262144|15663105|0|m,a,s,p"
	v := Score(fp)
	if !hasRule(v, "h2-vs-ua") {
		t.Errorf("a differing shared SETTINGS value should flag h2-vs-ua: %+v", v.Violations)
	}
	if v.Label == "spoofed" {
		t.Errorf("one H2 settings mismatch alone (medium) must not reach spoofed, got %s/%d", v.Label, v.SpoofScore)
	}
}

func TestUnrecognizedBrowserUAStillScored(t *testing.T) {
	fp := model.Fingerprint{
		UserAgent:   "Mozilla/5.0 (iPhone; CPU iPhone OS 26_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/150.0.7258.0 Mobile/15E148 Safari/604.1",
		HTTPVersion: "2",
		PseudoOrder: "a,m,p,s",
	}
	v := Score(fp)
	if v.Label == "not-a-browser-claim" {
		t.Errorf("a browser-shaped UA (CriOS) with a bot fingerprint must not get a free pass, got %s", v.Label)
	}
	if !hasRule(v, "bot-fingerprint") {
		t.Errorf("CriOS + Go pseudo-order should trip bot-fingerprint, got %+v", v.Violations)
	}
}

func TestHonestCurlStillNotABrowserClaim(t *testing.T) {
	fp := model.Fingerprint{UserAgent: "curl/8.12.1", HTTPVersion: "2", PseudoOrder: "a,m,p,s"}
	if v := Score(fp); v.Label != "not-a-browser-claim" {
		t.Errorf("an honest curl UA should be not-a-browser-claim, got %s", v.Label)
	}
}

func TestFirefoxFingerprintChromeUAIsSpoofed(t *testing.T) {
	fp := realFirefox()
	fp.UserAgent = chromeUA("151")
	v := Score(fp)
	if v.Label != "spoofed" {
		t.Errorf("Firefox-fingerprint + Chrome-UA should be spoofed, got %s/%d", v.Label, v.SpoofScore)
	}
	if !hasRule(v, "ja4-vs-ua") {
		t.Error("expected ja4-vs-ua mismatch to fire")
	}
}

func TestNoGREASEClaimingBrowserIsSpoofed(t *testing.T) {
	fp := realChrome()
	fp.GREASEPresent = false
	v := Score(fp)
	if v.Label != "spoofed" || !hasRule(v, "no-grease") {
		t.Errorf("no-GREASE browser should be spoofed via no-grease, got %s/%d", v.Label, v.SpoofScore)
	}
}

func TestHonestCurlIsNotSpoofed(t *testing.T) {
	fp := model.Fingerprint{
		JA4:         "t13d4907h2_abcabcabcabc_defdefdefdef",
		UserAgent:   "curl/8.5.0",
		HTTPVersion: "2",
		PseudoOrder: "m,s,a,p",
	}
	v := Score(fp)
	if v.Label == "spoofed" || v.SpoofScore != 0 {
		t.Errorf("honest curl should not be flagged, got %s/%d", v.Label, v.SpoofScore)
	}
}

func TestMissingMLKEMChromeIsSuspicious(t *testing.T) {
	fp := realChrome()
	fp.HasMLKEM = false
	v := Score(fp)
	if v.Label != "suspicious" || !hasRule(v, "missing-pq-keyshare") {
		t.Errorf("Chrome without MLKEM should be suspicious, got %s/%d %+v", v.Label, v.SpoofScore, v.Violations)
	}
}

func TestRealFirefoxNoGREASEIsConsistent(t *testing.T) {
	fp := realFirefox()
	if fp.GREASEPresent {
		t.Fatal("fixture bug: real Firefox sends no GREASE")
	}
	v := Score(fp)
	if hasRule(v, "no-grease") {
		t.Errorf("Firefox sends no GREASE by design — no-grease must not fire: %+v", v.Violations)
	}
	if v.Label != "consistent" || v.SpoofScore != 0 {
		t.Errorf("real Firefox must be consistent/0, got %s/%d %+v", v.Label, v.SpoofScore, v.Violations)
	}
}

func TestChrome17ExtNotMisreadAsSafari(t *testing.T) {
	fp := realChrome()
	fp.JA4 = "t13d1517h2_8daaf6152771_aabbccddeeff"
	v := Score(fp)
	if hasRule(v, "ja4-vs-ua") {
		t.Error("17-ext Chrome shares Safari's prefix but the cipher hash is Chromium — ja4-vs-ua must not fire")
	}
	if v.Label != "consistent" || v.SpoofScore != 0 {
		t.Errorf("17-ext Chrome must stay consistent, got %s/%d %+v", v.Label, v.SpoofScore, v.Violations)
	}
}

func TestChromeVaryingH2PriorityStillConsistent(t *testing.T) {
	fp := realChrome()
	fp.AkamaiH2 = "1:65536;2:0;4:6291456;6:262144|15663105|1:1:0:220|m,a,s,p"
	v := Score(fp)
	if hasRule(v, "h2-vs-ua") {
		t.Error("a different H2 priority weight must not trip h2-vs-ua")
	}
	if v.Label != "consistent" {
		t.Errorf("Chrome with a varied H2 priority must stay consistent, got %s/%d %+v", v.Label, v.SpoofScore, v.Violations)
	}
}

func TestWrongH2SettingsStillCaught(t *testing.T) {
	fp := realChrome()
	fp.AkamaiH2 = "1:65536;4:131072;5:16384|12517377|0|m,a,s,p"
	v := Score(fp)
	if !hasRule(v, "h2-vs-ua") {
		t.Errorf("wrong SETTINGS on a Chrome claim must trip h2-vs-ua: %+v", v.Violations)
	}
}

func TestMissingALPSChromeIsSuspicious(t *testing.T) {
	fp := realChrome()
	fp.HasALPS = false
	v := Score(fp)
	if v.Label != "suspicious" || !hasRule(v, "missing-alps") {
		t.Errorf("Chrome without ALPS should be suspicious via missing-alps, got %s/%d %+v", v.Label, v.SpoofScore, v.Violations)
	}
}

func TestRealSafariNotFlaggedForPQorALPS(t *testing.T) {
	v := Score(realSafari())
	if hasRule(v, "missing-pq-keyshare") {
		t.Error("real Safari 26 ships MLKEM — must not fire missing-pq-keyshare")
	}
	if hasRule(v, "missing-alps") {
		t.Error("Safari never sends ALPS — the ALPS rule must not apply to it")
	}
	if v.Label != "consistent" || v.SpoofScore != 0 {
		t.Errorf("real Safari should be consistent/0, got %s/%d %+v", v.Label, v.SpoofScore, v.Violations)
	}
}

func TestRealFirefoxNotFlaggedForALPS(t *testing.T) {
	if v := Score(realFirefox()); hasRule(v, "missing-alps") {
		t.Errorf("Firefox never sends ALPS — the rule must not apply, got %+v", v.Violations)
	}
}

func TestSecCHUAVersionMismatchIsSuspicious(t *testing.T) {
	fp := realChrome()
	fp.SecCHUA = `"Google Chrome";v="130", "Chromium";v="130"`
	v := Score(fp)
	if !hasRule(v, "sec-ch-ua-version") {
		t.Errorf("sec-ch-ua version mismatch should fire, got %+v", v.Violations)
	}
}

func TestHTTP1BrowserIsFlagged(t *testing.T) {
	fp := realChrome()
	fp.HTTPVersion = "1.1"
	v := Score(fp)
	if !hasRule(v, "http1-only") {
		t.Error("HTTP/1.1-only browser claim should fire http1-only")
	}
}

// An unrecognized (Unknown) UA whose JA4 matches a known browser is corroboration,
// not a violation — ja4-vs-ua only fires when the UA names a specific browser.
// Covers a real Chrome driven with a reduced UA string, and real iOS Chrome
// (CriOS runs on WebKit, so its JA4 is Safari's).
func TestUnknownUAWithBrowserJA4IsNotSpoofed(t *testing.T) {
	cases := map[string]model.Fingerprint{
		"reduced-desktop-chrome": {
			JA4:           "t13d1516h2_8daaf6152771_02713d6af862", // real Chrome
			UserAgent:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			HTTPVersion:   "2",
			PseudoOrder:   "m,a,s,p",
			GREASEPresent: true,
			HasMLKEM:      true,
			HasALPS:       true,
		},
		"ios-chrome-webkit": {
			JA4:           "t13d1517h2_a09f3c656075_14788d8d241b", // WebKit / Safari cipher hash
			UserAgent:     "Mozilla/5.0 (iPhone; CPU iPhone OS 26_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/150.0.7258.0 Mobile/15E148 Safari/604.1",
			HTTPVersion:   "2",
			PseudoOrder:   "m,s,p,a",
			GREASEPresent: true,
			HasMLKEM:      true,
		},
	}
	for name, fp := range cases {
		v := Score(fp)
		if hasRule(v, "ja4-vs-ua") {
			t.Errorf("%s: an unrecognized UA matching a real browser JA4 must not fire ja4-vs-ua: %+v", name, v.Violations)
		}
		if v.Label == "spoofed" {
			t.Errorf("%s: a real browser with an unparsed UA must not be spoofed, got %s/%d %+v", name, v.Label, v.SpoofScore, v.Violations)
		}
	}
}

// A fragmented or malformed ClientHello parses to nothing, so JA4 is empty. A
// browser claim over a completed TLS+HTTP connection with no readable hello must
// fail closed (spoofed), not fail open — even when the H2 shape looks perfect.
func TestBrowserClaimWithNoParseableHelloFailsClosed(t *testing.T) {
	fp := model.Fingerprint{
		UserAgent:   chromeUA("151"),
		HTTPVersion: "2",
		AkamaiH2:    "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p", // a perfect Chrome H2 shape must not rescue it
		PseudoOrder: "m,a,s,p",
	}
	v := Score(fp)
	if !hasRule(v, "no-tls-fingerprint") {
		t.Errorf("empty JA4 on a browser claim must fire no-tls-fingerprint, got %+v", v.Violations)
	}
	if v.Label != "spoofed" {
		t.Errorf("a browser claim with no readable ClientHello must be spoofed, got %s/%d %+v", v.Label, v.SpoofScore, v.Violations)
	}
}

// Absent high-signal H2 values are anomalous, not a free pass: a Chrome claim
// that omits the connection window, or overlaps barely any of the profile's
// SETTINGS, trips h2-vs-ua on a verified profile.
func TestH2AbsentValuesFailClosedOnVerifiedProfile(t *testing.T) {
	cases := map[string]string{
		"window-omitted":  "1:65536;2:0;4:6291456;6:262144||0|m,a,s,p",
		"one-setting-only": "1:65536|15663105|0|m,a,s,p",
	}
	for name, h2 := range cases {
		fp := realChrome()
		fp.AkamaiH2 = h2
		if v := Score(fp); !hasRule(v, "h2-vs-ua") {
			t.Errorf("%s: an absent high-signal H2 value on a verified profile must trip h2-vs-ua, got %+v", name, v.Violations)
		}
	}
}

// The absent-value checks must NOT apply to an assumed (uncaptured) profile, or
// Safari — whose values aren't measured — would false-positive.
func TestH2AbsentValuesLenientOnAssumedSafari(t *testing.T) {
	if p, _ := profiles.ByFamily(model.Safari); p.CapturedOn != "" {
		t.Skip("Safari profile is now captured; this gate no longer applies")
	}
	fp := realSafari()
	fp.AkamaiH2 = "2:0;4:4194304;3:100||0|m,s,p,a" // window omitted
	if v := Score(fp); hasRule(v, "h2-vs-ua") {
		t.Errorf("an assumed profile must stay lenient on absent values, got %+v", v.Violations)
	}
}

// A browser-claiming client that opens with no SETTINGS frame is anomalous —
// real browsers always send one — so it must not be exempt from h2-vs-ua.
func TestEmptyH2SettingsFromBrowserClaimIsFlagged(t *testing.T) {
	fp := realChrome()
	fp.AkamaiH2 = "|15663105|0|m,a,s,p" // no SETTINGS
	if v := Score(fp); !hasRule(v, "h2-vs-ua") {
		t.Errorf("an empty SETTINGS frame on a browser claim must trip h2-vs-ua, got %+v", v.Violations)
	}
}

// The connection window is compared, not just SETTINGS: a client replaying
// Chrome's SETTINGS with Firefox's window (12517377 vs Chrome's 15663105) must
// trip h2-vs-ua.
func TestH2WindowMismatchTripsH2(t *testing.T) {
	fp := realChrome()
	fp.AkamaiH2 = "1:65536;2:0;4:6291456;6:262144|12517377|0|m,a,s,p"
	if v := Score(fp); !hasRule(v, "h2-vs-ua") {
		t.Errorf("a wrong connection window must trip h2-vs-ua, got %+v", v.Violations)
	}
}

func hasRule(v model.Verdict, rule string) bool {
	for _, x := range v.Violations {
		if x.Rule == rule {
			return true
		}
	}
	return false
}
