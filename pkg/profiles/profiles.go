package profiles

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/NotChaosuu/spoofprint/pkg/model"
)

// active is the profile set the scorer consults. It starts from the built-in
// defaults and can be overridden at runtime with LoadProfiles, so refreshing a
// profile after a browser release is a config change, not a new binary.
var active = defaultBrowsers()

// Browsers returns the active profile set (built-in defaults plus any runtime
// overrides loaded via LoadProfiles).
func Browsers() []model.Profile { return active }

func defaultBrowsers() []model.Profile {
	return []model.Profile{
		{
			Name:          "Chrome",
			Family:        model.Chrome,
			JA4Prefix:     "t13d1516h2",
			JA4CipherHash: "8daaf6152771",
			// d8a2.. and b6f4.. are the 16- and 17-extension Chrome 151 captures;
			// cb7bf5808d99 is Chrome 152+, from its published JA4_r.
			JA4ExtHashes:  []string{"d8a2da3f94cd", "b6f405a00624", "cb7bf5808d99"},
			AkamaiH2:      "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
			PseudoOrder:   "m,a,s,p",
			ExpectsMLKEM:  true,
			ExpectsALPS:   true,
			ExpectsGREASE: true,
			UATokens:      []string{"Chrome/"},
			CapturedOn:    "2026-07-29",
			Versions:      "Chrome 149–151 (Windows)",
		},
		{
			Name:          "Edge",
			Family:        model.Edge,
			JA4Prefix:     "t13d1516h2",
			JA4CipherHash: "8daaf6152771",
			JA4ExtHashes:  []string{"806a8c22fdea", "a87ad97598a9"},
			AkamaiH2:      "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
			PseudoOrder:   "m,a,s,p",
			ExpectsMLKEM:  true,
			ExpectsALPS:   true,
			ExpectsGREASE: true,
			UATokens:      []string{"Edg/"},
			CapturedOn:    "2026-07-29",
			Versions:      "Edge 150 (Windows)",
		},
		{
			// H2 captured from real Firefox 153 (settings include 2:0 = ENABLE_PUSH
			// off, which FF 132+ sends; the priority field is one HEADERS frame with
			// a varying weight, not the old dependency tree — it's excluded from
			// matching). Cipher hash 86a278354501 is the 16-cipher list Firefox sent
			// up to 153. Firefox 154 dropped one cipher and now sends exactly
			// Chrome's 15, so its JA4_b is Chrome's 8daaf6152771 and the family has
			// to come from the extensions instead (see FamilyFromFingerprint). The
			// extension set didn't change, so JA4_c is 3cbfd9057e0d on both.
			Name:            "Firefox",
			Family:          model.Firefox,
			JA4Prefix:       "t13d1617h2",
			JA4CipherHash:   "86a278354501",
			AltCipherHashes: []string{"8daaf6152771"},
			JA4ExtHashes:    []string{"3cbfd9057e0d"},
			AkamaiH2:        "1:65536;2:0;4:131072;5:16384|12517377|3:0:0:42|m,p,a,s",
			PseudoOrder:     "m,p,a,s",
			ExpectsMLKEM:    true,
			ExpectsALPS:     false,
			ExpectsGREASE:   false,
			UATokens:        []string{"Firefox/"},
			CapturedOn:      "2026-07-29",
			Versions:        "Firefox 153 / Gecko 141 (Windows); 154+ cipher list from its published JA4_r",
		},
		{
			// Safari doesn't run on the Windows box the other captures came from,
			// so these values are taken from curl-impersonate's published Safari
			// signatures (lexiforest/curl-impersonate, tests/signatures). The main
			// H2 string is safari_26.0.1_macOS; 18.0 through 27 send the same
			// order and window. Safari 17 opened differently (m,s,p,a, window
			// 10485760); it's kept as an alternate because iPhones that can't move
			// past iOS 17 still browse, and they already score suspicious for the
			// missing ML-KEM share. CapturedOn stays empty: we haven't captured
			// Safari ourselves, so the absent-value H2 checks stay off for it.
			Name:          "Safari",
			Family:        model.Safari,
			JA4Prefix:     "t13d2014h2",
			JA4CipherHash: "a09f3c656075",
			AkamaiH2:      "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p",
			AltAkamaiH2: []string{
				"2:0;4:4194304;3:100|10485760|0|m,s,p,a", // Safari 17.0 macOS
				"2:0;4:2097152;3:100|10485760|0|m,s,p,a", // Safari 17.2 iOS
			},
			PseudoOrder:   "m,s,a,p",
			ExpectsMLKEM:  true,
			ExpectsALPS:   false,
			ExpectsGREASE: true,
			UATokens:      []string{"Version/"},
			Versions:      "Safari 18–27 (from curl-impersonate signatures, not captured here); Safari 17 H2 accepted",
		},
	}
}

// LoadProfiles merges profiles from JSON (an array of the Profile shape) into the
// active set: an entry replaces the built-in of the same family, or is appended
// as a new family. Returns the number applied. This is how you keep spoofprint
// current between releases — capture a real browser, drop the JSON in, restart.
func LoadProfiles(data []byte) (int, error) {
	var incoming []model.Profile
	if err := json.Unmarshal(data, &incoming); err != nil {
		return 0, fmt.Errorf("profiles: %w", err)
	}
	for _, p := range incoming {
		if p.Family == "" || p.JA4CipherHash == "" {
			return 0, fmt.Errorf("profiles: entry %q missing family or ja4_cipher_hash", p.Name)
		}
		replaced := false
		for i := range active {
			if active[i].Family == p.Family {
				active[i] = p
				replaced = true
				break
			}
		}
		if !replaced {
			active = append(active, p)
		}
	}
	return len(incoming), nil
}

// LoadProfilesFile applies LoadProfiles to a file on disk.
func LoadProfilesFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return LoadProfiles(data)
}

// StaleProfiles returns a human-readable warning for every active profile whose
// reference values are older than maxAge (as of now) or were never captured.
// A stale profile is the likeliest cause of a surprising verdict, so surfacing it
// turns a silent time bomb into a startup warning.
func StaleProfiles(now time.Time, maxAge time.Duration) []string {
	var out []string
	for _, p := range active {
		if p.CapturedOn == "" {
			out = append(out, p.Name+": values were not captured here (assumed or third-party)")
			continue
		}
		t, err := time.Parse("2006-01-02", p.CapturedOn)
		if err != nil {
			out = append(out, p.Name+": unparseable captured_on "+p.CapturedOn)
			continue
		}
		if now.Sub(t) > maxAge {
			days := int(now.Sub(t).Hours() / 24)
			out = append(out, fmt.Sprintf("%s: captured %s (%d days ago) — recapture recommended", p.Name, p.CapturedOn, days))
		}
	}
	return out
}

// resetProfiles restores the built-in defaults; used by tests.
func resetProfiles() { active = defaultBrowsers() }

func BotSignatures() []model.BotSignature {
	return []model.BotSignature{
		{Name: "Go net/http", PseudoOrder: "a,m,p,s", UAToken: "Go-http-client",
			Detail: "Go's x/net/http2 writes pseudo-headers :authority,:method,:path,:scheme (a,m,p,s), matching no browser."},
		{Name: "curl", JA4Prefix: "t13d4907", UAToken: "curl/",
			Detail: "curl's default ClientHello advertises ~49 ciphers / 7 extensions — not a browser shape."},
		{Name: "python-requests", UAToken: "python-requests",
			Detail: "python-requests is HTTP/1.1 only with an OpenSSL ClientHello and no GREASE."},
		{Name: "Wget", UAToken: "Wget/",
			Detail: "wget is HTTP/1.1 only and sends Accept-Encoding: identity."},
		{Name: "Java HttpClient", UAToken: "Java-http-client",
			Detail: "Java's SunJSSE ClientHello has no GREASE and a non-browser cipher order."},
		{Name: "Node undici", UAToken: "undici",
			Detail: "Node undici sends a non-browser header set (accept-language: *)."},
	}
}

func ByFamily(fam model.Family) (model.Profile, bool) {
	for _, p := range Browsers() {
		if p.Family == fam {
			return p, true
		}
	}
	return model.Profile{}, false
}

func ClaimedBrowser(ua string) model.Family {
	switch {
	case strings.Contains(ua, "Edg/"):
		return model.Edge
	case strings.Contains(ua, "Chrome/") && !strings.Contains(ua, "Edg/"):
		return model.Chrome
	case strings.Contains(ua, "Firefox/"):
		return model.Firefox
	case strings.Contains(ua, "Version/") && strings.Contains(ua, "Safari/") && !strings.Contains(ua, "Chrome/"):
		return model.Safari
	default:
		return model.Unknown
	}
}

func JA4CipherHash(ja4 string) string {
	parts := strings.Split(ja4, "_")
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

// JA4ExtHash returns JA4_c, the hash of the sorted extensions and signature
// algorithms.
func JA4ExtHash(ja4 string) string {
	parts := strings.Split(ja4, "_")
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// FamilyFromJA4 names the browser family from a JA4 string alone. When the
// cipher hash belongs to one family that's the answer; when several families
// share it (Chrome and Firefox 154+ do), only a known JA4_c can settle it, and
// anything else is Unknown. Score uses FamilyFromFingerprint, which can also
// look at the ClientHello's shape.
func FamilyFromJA4(ja4 string) model.Family {
	return familyOf(ja4, nil)
}

// FamilyFromFingerprint is FamilyFromJA4 plus the ClientHello flags the
// capture already parsed. Those break a shared cipher hash: Chromium sends
// ALPS and GREASE, Firefox sends neither. If the evidence still doesn't point
// at exactly one family the answer is Unknown, so a fingerprint we can't place
// never turns into a confident ja4-vs-ua mismatch.
func FamilyFromFingerprint(fp model.Fingerprint) model.Family {
	return familyOf(fp.JA4, &fp)
}

func familyOf(ja4 string, fp *model.Fingerprint) model.Family {
	ch := JA4CipherHash(ja4)
	if ch == "" {
		return model.Unknown
	}
	// Edge is a Chromium build with the same TLS stack, so it counts as Chrome
	// here; ja4-vs-ua already treats the two as one family.
	byFamily := map[model.Family][]model.Profile{}
	var order []model.Family
	for _, p := range Browsers() {
		if !hasCipherHash(p, ch) {
			continue
		}
		fam := p.Family
		if fam == model.Edge {
			fam = model.Chrome
		}
		if _, seen := byFamily[fam]; !seen {
			order = append(order, fam)
		}
		byFamily[fam] = append(byFamily[fam], p)
	}
	switch len(order) {
	case 0:
		return model.Unknown
	case 1:
		return order[0]
	}

	if ext := JA4ExtHash(ja4); ext != "" {
		knownExt := func(p model.Profile) bool { return contains(p.JA4ExtHashes, ext) }
		if fam, ok := single(order, byFamily, knownExt); ok {
			return fam
		}
	}
	if fp != nil {
		shape := func(p model.Profile) bool {
			return fp.HasALPS == p.ExpectsALPS && fp.GREASEPresent == p.ExpectsGREASE
		}
		if fam, ok := single(order, byFamily, shape); ok {
			return fam
		}
	}
	return model.Unknown
}

// single returns the family with a profile matching ok, if exactly one has.
func single(order []model.Family, byFamily map[model.Family][]model.Profile, ok func(model.Profile) bool) (model.Family, bool) {
	var hit []model.Family
	for _, fam := range order {
		for _, p := range byFamily[fam] {
			if ok(p) {
				hit = append(hit, fam)
				break
			}
		}
	}
	if len(hit) == 1 {
		return hit[0], true
	}
	return model.Unknown, false
}

func hasCipherHash(p model.Profile, ch string) bool {
	return p.JA4CipherHash == ch || contains(p.AltCipherHashes, ch)
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
