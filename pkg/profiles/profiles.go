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
			// matching). Cipher hash 86a278354501 is the sorted-cipher JA4 part B.
			Name:          "Firefox",
			Family:        model.Firefox,
			JA4Prefix:     "t13d1617h2",
			JA4CipherHash: "86a278354501",
			AkamaiH2:      "1:65536;2:0;4:131072;5:16384|12517377|3:0:0:42|m,p,a,s",
			PseudoOrder:   "m,p,a,s",
			ExpectsMLKEM:  true,
			ExpectsALPS:   false,
			ExpectsGREASE: false,
			UATokens:      []string{"Firefox/"},
			CapturedOn:    "2026-07-29",
			Versions:      "Firefox 153 / Gecko 141 (Windows)",
		},
		{
			// Safari values are ASSUMED, not captured — Safari doesn't run on the
			// Windows box these captures came from. Empty CapturedOn flags it as
			// unverified so StaleProfiles surfaces it; a wrong Safari value fails
			// open to "unknown" rather than mislabeling.
			Name:          "Safari",
			Family:        model.Safari,
			JA4Prefix:     "t13d1517h2",
			JA4CipherHash: "a09f3c656075",
			AkamaiH2:      "2:0;4:4194304;3:100|10485760|0|m,s,p,a",
			PseudoOrder:   "m,s,p,a",
			ExpectsMLKEM:  true,
			ExpectsALPS:   false,
			ExpectsGREASE: true,
			UATokens:      []string{"Version/"},
			Versions:      "Safari 26 (assumed, not captured)",
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
			out = append(out, p.Name+": values are assumed, not captured")
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

func FamilyFromJA4(ja4 string) model.Family {
	ch := JA4CipherHash(ja4)
	if ch == "" {
		return model.Unknown
	}
	for _, p := range Browsers() {
		if p.JA4CipherHash == ch {
			if p.Family == model.Edge {
				continue
			}
			return p.Family
		}
	}
	return model.Unknown
}
