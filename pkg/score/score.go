package score

import (
	"strings"

	"github.com/NotChaosuu/spoofprint/pkg/model"
	"github.com/NotChaosuu/spoofprint/pkg/profiles"
)

const (
	weightHigh   = 40
	weightMedium = 15
	weightLow    = 5
)

func Score(fp model.Fingerprint) model.Verdict {
	claimed := profiles.ClaimedBrowser(fp.UserAgent)
	fpFam := profiles.FamilyFromFingerprint(fp)

	v := model.Verdict{
		Fingerprint:    fp,
		ClaimedBrowser: claimed,
		FingerprintFam: fpFam,
	}

	if !isBrowser(claimed) {
		if !looksLikeBrowserUA(fp.UserAgent) {
			v.Label = "not-a-browser-claim"
			return v
		}
	}

	claimedProfile, hasProfile := profiles.ByFamily(claimed)

	add := func(rule string, sev model.Severity, detail string) {
		v.Violations = append(v.Violations, model.Violation{Rule: rule, Severity: sev, Detail: detail})
	}

	// Only a UA that maps to a specific browser family can contradict its JA4.
	// For an unrecognized (Unknown) UA, a JA4 that matches a known browser is
	// corroborating evidence, not a violation — otherwise real iOS Chrome and
	// in-app webviews (WebKit engine, exotic UA) would all be flagged.
	if isBrowser(claimed) && fp.JA4 != "" && fpFam != model.Unknown && !sameFamily(claimed, fpFam) {
		add("ja4-vs-ua", model.High,
			"User-Agent claims "+string(claimed)+" but the TLS (JA4) fingerprint matches "+string(fpFam)+".")
	}

	// Fail closed: a browser-shaped request over a completed TLS+HTTP connection
	// must yield a parseable ClientHello. An empty JA4 here means capture/parse
	// failed (e.g. a deliberately fragmented or malformed hello). Not reading the
	// fingerprint must cost points, not earn a pass.
	if fp.JA4 == "" && fp.HTTPVersion != "" && (isBrowser(claimed) || looksLikeBrowserUA(fp.UserAgent)) {
		add("no-tls-fingerprint", model.High,
			"Claims a browser over TLS but no valid ClientHello could be parsed; a real browser always produces one (a fragmented or malformed hello reads as none).")
	}

	if hasProfile && fp.AkamaiH2 != "" && !h2MatchesProfile(fp.AkamaiH2, claimedProfile) {
		add("h2-vs-ua", model.Medium,
			"HTTP/2 fingerprint disagrees with "+claimedProfile.Name+"'s known values (a declared SETTING or the connection window differs, is missing, or the SETTINGS barely overlap).")
	}

	if hasProfile && fp.PseudoOrder != "" {
		if orders := pseudoOrders(claimedProfile); !containsStr(orders, fp.PseudoOrder) {
			add("pseudo-order", model.High,
				"HTTP/2 pseudo-header order "+fp.PseudoOrder+" does not match "+claimedProfile.Name+"'s ("+strings.Join(orders, " or ")+").")
		}
	}

	if hasProfile && claimedProfile.ExpectsGREASE && fp.JA4 != "" && !fp.GREASEPresent {
		add("no-grease", model.High,
			"Claims "+claimedProfile.Name+" but the TLS ClientHello contains no GREASE values; a real "+claimedProfile.Name+" injects GREASE.")
	}

	if fp.HTTPVersion == "1.1" {
		add("http1-only", model.Medium,
			"Claims a modern browser but negotiated only HTTP/1.1; browsers use HTTP/2 over TLS.")
	}

	if hasProfile && claimedProfile.ExpectsMLKEM && fp.JA4 != "" && !fp.HasMLKEM {
		add("missing-pq-keyshare", model.Medium,
			"Claims "+claimedProfile.Name+" but the ClientHello lacks the X25519MLKEM768 post-quantum key share that current "+claimedProfile.Name+" sends.")
	}

	if hasProfile && claimedProfile.ExpectsALPS && fp.JA4 != "" && !fp.HasALPS {
		add("missing-alps", model.Medium,
			"Claims "+claimedProfile.Name+" but the ClientHello lacks the application_settings (ALPS) extension that every Chromium browser sends.")
	}

	if uaMaj := chromeMajor(fp.UserAgent); uaMaj != "" && fp.SecCHUA != "" {
		if majors := secCHUAMajors(fp.SecCHUA); len(majors) > 0 && !containsStr(majors, uaMaj) {
			add("sec-ch-ua-version", model.Medium,
				"sec-ch-ua brand versions ["+strings.Join(majors, ",")+"] do not include the User-Agent version "+uaMaj+".")
		}
	}

	for _, sig := range profiles.BotSignatures() {
		if sig.JA4Prefix != "" && fp.JA4 != "" && strings.HasPrefix(fp.JA4, sig.JA4Prefix) {
			add("bot-fingerprint", model.High,
				"Claims a browser but the TLS fingerprint matches "+sig.Name+": "+sig.Detail)
			break
		}
		if sig.PseudoOrder != "" && fp.PseudoOrder != "" && fp.PseudoOrder == sig.PseudoOrder {
			add("bot-fingerprint", model.High,
				"Claims a browser but the HTTP/2 fingerprint matches "+sig.Name+": "+sig.Detail)
			break
		}
	}

	v.SpoofScore = tally(v.Violations)
	v.Label = label(v.SpoofScore)
	return v
}

// h2MatchesProfile accepts the client's HTTP/2 opening if it is consistent with
// the profile's main Akamai string or with any of its older-release
// alternates.
func h2MatchesProfile(observed string, p model.Profile) bool {
	verified := p.CapturedOn != ""
	if h2Consistent(observed, p.AkamaiH2, verified) {
		return true
	}
	for _, alt := range p.AltAkamaiH2 {
		if h2Consistent(observed, alt, verified) {
			return true
		}
	}
	return false
}

// pseudoOrders lists the pseudo-header orders a profile accepts: its own, then
// the order field of each alternate Akamai string.
func pseudoOrders(p model.Profile) []string {
	out := []string{p.PseudoOrder}
	for _, alt := range p.AltAkamaiH2 {
		if o := field(fields(alt), 3); o != "" && !containsStr(out, o) {
			out = append(out, o)
		}
	}
	return out
}

// h2Consistent compares the Akamai HTTP/2 fingerprint against a profile on two
// axes:
//
//   - SETTINGS block: only the settings the profile actually declares matter, and
//     only when present in BOTH sides with a different value. Extra settings the
//     client sends and profile settings it omits are tolerated, because browsers
//     add/drop SETTINGS between releases — so one profile drift can't force a
//     spoofed verdict on its own.
//   - Connection window (WINDOW_UPDATE): one of the most stable, highest-signal
//     values in the fingerprint (Chrome 15663105, Firefox 12517377, Go
//     1073741824). Compared only when both sides are present and non-zero, so a
//     client that sends no window isn't penalised here.
//
// Pseudo-header order is scored by its own rule.
//
// verified is true when the profile's values were actually captured from a real
// browser (CapturedOn set). Only then do the *absent-value* checks apply — a real
// browser sends all of these on every connection, so omitting them is anomalous —
// because firing them against an assumed profile (Safari) could false-positive.
func h2Consistent(observed, profile string, verified bool) bool {
	of, pf := fields(observed), fields(profile)
	obs, prof := parseSettings(field(of, 0)), parseSettings(field(pf, 0))

	// A real browser always opens the connection with a non-empty SETTINGS frame.
	// An empty SETTINGS block against a profile that declares some is anomalous —
	// and closes the "zero settings is exempt from every comparison" gap.
	if len(prof) > 0 && len(obs) == 0 {
		return false
	}
	// Any SETTING present in both with a different value is a mismatch.
	shared := 0
	for id, pv := range prof {
		if ov, ok := obs[id]; ok {
			shared++
			if ov != pv {
				return false
			}
		}
	}
	ow, pw := field(of, 1), field(pf, 1)
	// Window present on both sides but different.
	if ow != "" && pw != "" && ow != "0" && pw != "0" && ow != pw {
		return false
	}

	// Fail closed on ABSENT high-signal values (verified profiles only). Same
	// reasoning as no-tls-fingerprint on the TLS side: not sending a value a real
	// browser always sends is itself a tell, not a free pass.
	if verified {
		// The profile declares a non-zero window and the client sent none.
		if pw != "" && pw != "0" && (ow == "" || ow == "0") {
			return false
		}
		// The client's SETTINGS overlap fewer than half the profile's declared
		// ones (e.g. sends just 1:65536 against a four-setting profile).
		if len(prof) > 0 && shared*2 < len(prof) {
			return false
		}
	}
	return true
}

func fields(s string) []string { return strings.Split(s, "|") }

func field(fs []string, i int) string {
	if i < len(fs) {
		return fs[i]
	}
	return ""
}

func parseSettings(s string) map[string]string {
	m := map[string]string{}
	for _, kv := range strings.Split(s, ";") {
		if id, val, ok := strings.Cut(kv, ":"); ok {
			m[id] = val
		}
	}
	return m
}

// looksLikeBrowserUA reports whether a UA claims to be a browser we should still
// score even without a per-browser profile. A known CLI/library UA (curl, Go,
// python-requests) is an honest non-browser and short-circuits to
// "not-a-browser-claim"; an unrecognized-but-browser-shaped UA (CriOS, FxiOS,
// SamsungBrowser, ...) must NOT get a free pass, so it falls through to the
// profile-independent checks (bot-fingerprint, http1-only).
func looksLikeBrowserUA(ua string) bool {
	if !strings.Contains(ua, "Mozilla/") {
		return false
	}
	for _, sig := range profiles.BotSignatures() {
		if sig.UAToken != "" && strings.Contains(ua, sig.UAToken) {
			return false
		}
	}
	for _, tool := range []string{"curl/", "Wget/", "python-requests", "Go-http-client", "Java/", "okhttp", "axios", "node-fetch", "PostmanRuntime", "Apache-HttpClient", "libwww", "Scrapy", "aiohttp", "HTTPie"} {
		if strings.Contains(ua, tool) {
			return false
		}
	}
	return true
}

func tally(vs []model.Violation) int {
	total := 0
	for _, x := range vs {
		switch x.Severity {
		case model.High:
			total += weightHigh
		case model.Medium:
			total += weightMedium
		case model.Low:
			total += weightLow
		}
	}
	if total > 100 {
		total = 100
	}
	return total
}

func label(score int) string {
	switch {
	case score >= 40:
		return "spoofed"
	case score >= 1:
		return "suspicious"
	default:
		return "consistent"
	}
}

func isBrowser(f model.Family) bool {
	switch f {
	case model.Chrome, model.Firefox, model.Safari, model.Edge:
		return true
	}
	return false
}

func sameFamily(a, b model.Family) bool {
	if a == b {
		return true
	}
	chromium := func(f model.Family) bool { return f == model.Chrome || f == model.Edge }
	return chromium(a) && chromium(b)
}

func chromeMajor(ua string) string {
	for _, tok := range []string{"Chrome/", "Edg/"} {
		if i := strings.Index(ua, tok); i >= 0 {
			return leadingDigits(ua[i+len(tok):])
		}
	}
	return ""
}

func secCHUAMajors(s string) []string {
	var out []string
	for _, seg := range strings.Split(s, ",") {
		if i := strings.Index(seg, `v="`); i >= 0 {
			if maj := leadingDigits(seg[i+3:]); maj != "" {
				out = append(out, maj)
			}
		}
	}
	return out
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func leadingDigits(s string) string {
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	return s[:n]
}
