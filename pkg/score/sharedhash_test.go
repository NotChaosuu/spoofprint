package score

import (
	"strconv"
	"strings"
	"testing"

	"github.com/NotChaosuu/spoofprint/pkg/model"
	"github.com/NotChaosuu/spoofprint/pkg/profiles"
	"github.com/NotChaosuu/spoofprint/pkg/tlscapture"
)

// Published JA4_r strings. Firefox 154 sends the same 15 ciphers as Chrome 152,
// so both have JA4_b 8daaf6152771; only the extensions tell them apart.
const (
	firefox154JA4r = "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,001c,0022,0023,002b,002d,0033,fe0d,ff01_0403,0503,0603,0804,0805,0806,0401,0501,0601,0203,0201"
	chrome152JA4r  = "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ca34,fe0d,ff01_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"

	firefox154JA4 = "t13d1517h2_8daaf6152771_3cbfd9057e0d"
	chrome152JA4  = "t13d1517h2_8daaf6152771_cb7bf5808d99"

	firefox154UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:154.0) Gecko/20100101 Firefox/154.0"
	firefoxH2    = "1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s"
	chromeH2     = "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
)

// helloFromJA4r builds a ClientHello carrying the ciphers, extensions and
// signature algorithms of a JA4_r string, plus SNI and ALPN (which JA4_r leaves
// out of its extension list). With grease set it adds a GREASE cipher and
// extension the way Chromium does.
func helloFromJA4r(t *testing.T, ja4r string, grease bool) []byte {
	t.Helper()
	parts := strings.Split(ja4r, "_")
	if len(parts) != 4 {
		t.Fatalf("bad JA4_r %q", ja4r)
	}
	ciphers, exts, sigalgs := hexList(t, parts[1]), hexList(t, parts[2]), hexList(t, parts[3])
	if grease {
		ciphers = append([]uint16{0x0a0a}, ciphers...)
		exts = append([]uint16{0x1a1a}, exts...)
	}
	exts = append([]uint16{0x0000, 0x0010}, exts...)

	var b []byte
	put16 := func(dst *[]byte, v uint16) { *dst = append(*dst, byte(v>>8), byte(v)) }

	b = append(b, 0x03, 0x03)
	b = append(b, make([]byte, 32)...)
	b = append(b, 0x00)
	put16(&b, uint16(2*len(ciphers)))
	for _, c := range ciphers {
		put16(&b, c)
	}
	b = append(b, 0x01, 0x00)

	var ext []byte
	for _, e := range exts {
		var body []byte
		switch e {
		case 0x000a: // supported_groups with X25519MLKEM768 first
			body = []byte{0x00, 0x04, 0x11, 0xec, 0x00, 0x1d}
		case 0x000d:
			put16(&body, uint16(2*len(sigalgs)))
			for _, s := range sigalgs {
				put16(&body, s)
			}
		case 0x0010:
			body = []byte{0x00, 0x0c, 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'}
		case 0x002b:
			body = []byte{0x04, 0x03, 0x04, 0x03, 0x03}
		}
		put16(&ext, e)
		put16(&ext, uint16(len(body)))
		ext = append(ext, body...)
	}
	put16(&b, uint16(len(ext)))
	b = append(b, ext...)

	hdr := []byte{0x01, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}
	return append(hdr, b...)
}

func hexList(t *testing.T, s string) []uint16 {
	t.Helper()
	var out []uint16
	for _, h := range strings.Split(s, ",") {
		v, err := strconv.ParseUint(h, 16, 16)
		if err != nil {
			t.Fatalf("bad hex %q: %v", h, err)
		}
		out = append(out, uint16(v))
	}
	return out
}

// fingerprintFromHello fills the TLS fields the same way cmd/collector does.
func fingerprintFromHello(t *testing.T, hello []byte, wantJA4 string) model.Fingerprint {
	t.Helper()
	parsed, err := tlscapture.ParseClientHello(hello)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	fp := model.Fingerprint{
		JA4:           parsed.JA4(false),
		GREASEPresent: parsed.GREASEPresent,
		HasMLKEM:      parsed.HasMLKEM,
		HasALPS:       parsed.HasALPS,
		ALPN:          parsed.ALPN,
		HTTPVersion:   "2",
	}
	if fp.JA4 != wantJA4 {
		t.Fatalf("built hello has JA4 %s, want %s", fp.JA4, wantJA4)
	}
	return fp
}

func firefox154(t *testing.T) model.Fingerprint {
	fp := fingerprintFromHello(t, helloFromJA4r(t, firefox154JA4r, false), firefox154JA4)
	fp.UserAgent = firefox154UA
	fp.AkamaiH2 = firefoxH2
	fp.PseudoOrder = "m,p,a,s"
	return fp
}

func chrome152(t *testing.T) model.Fingerprint {
	fp := fingerprintFromHello(t, helloFromJA4r(t, chrome152JA4r, true), chrome152JA4)
	fp.UserAgent = chromeUA("152")
	fp.SecCHUA = `"Google Chrome";v="152", "Chromium";v="152", "Not(A:Brand";v="24"`
	fp.AkamaiH2 = chromeH2
	fp.PseudoOrder = "m,a,s,p"
	return fp
}

func TestRealFirefox154IsConsistent(t *testing.T) {
	v := Score(firefox154(t))
	if hasRule(v, "ja4-vs-ua") {
		t.Errorf("Firefox 154 shares Chrome's cipher hash; its own UA must not trip ja4-vs-ua: %+v", v.Violations)
	}
	if v.FingerprintFam != model.Firefox {
		t.Errorf("fingerprint family = %s, want firefox", v.FingerprintFam)
	}
	if v.Label != "consistent" || v.SpoofScore != 0 {
		t.Errorf("real Firefox 154 must be consistent/0, got %s/%d %+v", v.Label, v.SpoofScore, v.Violations)
	}
}

func TestRealChrome152IsConsistent(t *testing.T) {
	v := Score(chrome152(t))
	if v.FingerprintFam != model.Chrome || v.Label != "consistent" || v.SpoofScore != 0 {
		t.Errorf("real Chrome 152 must be chrome/consistent/0, got %s/%s/%d %+v", v.FingerprintFam, v.Label, v.SpoofScore, v.Violations)
	}
}

func TestChromeUAOnFirefox154HelloIsFlagged(t *testing.T) {
	fp := firefox154(t)
	fp.UserAgent = chromeUA("152")
	fp.AkamaiH2 = chromeH2
	fp.PseudoOrder = "m,a,s,p"
	v := Score(fp)
	if !hasRule(v, "ja4-vs-ua") || v.Label != "spoofed" {
		t.Errorf("Chrome UA over a Firefox 154 hello must be spoofed via ja4-vs-ua, got %s/%d %+v", v.Label, v.SpoofScore, v.Violations)
	}
}

func TestFirefoxUAOnChrome152HelloIsFlagged(t *testing.T) {
	fp := chrome152(t)
	fp.UserAgent = firefox154UA
	fp.SecCHUA = ""
	fp.AkamaiH2 = firefoxH2
	fp.PseudoOrder = "m,p,a,s"
	v := Score(fp)
	if !hasRule(v, "ja4-vs-ua") || v.Label != "spoofed" {
		t.Errorf("Firefox UA over a Chrome 152 hello must be spoofed via ja4-vs-ua, got %s/%d %+v", v.Label, v.SpoofScore, v.Violations)
	}
}

// A Chromium hello whose JA4_c isn't in any profile (a new Chrome build) still
// shows ALPS and GREASE, which is enough to call it Chrome under a Firefox UA.
func TestFirefoxUAOnUnlistedChromeHelloIsFlagged(t *testing.T) {
	fp := realChrome()
	fp.JA4 = "t13d1517h2_8daaf6152771_aabbccddeeff"
	fp.UserAgent = firefox154UA
	fp.SecCHUA = ""
	fp.AkamaiH2 = firefoxH2
	fp.PseudoOrder = "m,p,a,s"
	if v := Score(fp); !hasRule(v, "ja4-vs-ua") {
		t.Errorf("ALPS+GREASE on the shared cipher hash is Chromium; a Firefox UA must trip ja4-vs-ua: %+v", v.Violations)
	}
}

// When neither JA4_c nor the hello's shape settles a shared cipher hash, the
// family is Unknown and ja4-vs-ua stays quiet rather than guessing.
func TestSharedCipherHashWithMixedShapeFailsOpen(t *testing.T) {
	fp := realChrome()
	fp.JA4 = "t13d1517h2_8daaf6152771_aabbccddeeff"
	fp.GREASEPresent = false // ALPS but no GREASE: neither Chromium nor Firefox
	fp.UserAgent = firefox154UA
	fp.SecCHUA = ""
	fp.AkamaiH2 = firefoxH2
	fp.PseudoOrder = "m,p,a,s"
	v := Score(fp)
	if v.FingerprintFam != model.Unknown {
		t.Errorf("ambiguous shared-hash hello must be unknown, got %s", v.FingerprintFam)
	}
	if hasRule(v, "ja4-vs-ua") {
		t.Errorf("an unplaceable fingerprint must not produce ja4-vs-ua: %+v", v.Violations)
	}
}

func TestOldFirefoxStillRecognised(t *testing.T) {
	v := Score(realFirefox())
	if v.FingerprintFam != model.Firefox || v.Label != "consistent" {
		t.Errorf("Firefox 153 (86a278354501) must still be firefox/consistent, got %s/%s %+v", v.FingerprintFam, v.Label, v.Violations)
	}
	fp := realFirefox()
	fp.UserAgent = chromeUA("151")
	if v := Score(fp); !hasRule(v, "ja4-vs-ua") {
		t.Errorf("Firefox 153 hello under a Chrome UA must still trip ja4-vs-ua: %+v", v.Violations)
	}
}

func TestRealSafari26H2HasNoPseudoOrderViolation(t *testing.T) {
	fp := realSafari()
	fp.AkamaiH2 = "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p"
	fp.PseudoOrder = "m,s,a,p"
	v := Score(fp)
	if hasRule(v, "pseudo-order") || hasRule(v, "h2-vs-ua") {
		t.Errorf("real Safari 26 H2 must match the Safari profile: %+v", v.Violations)
	}
	if v.Label != "consistent" {
		t.Errorf("real Safari 26 must be consistent, got %s/%d %+v", v.Label, v.SpoofScore, v.Violations)
	}
}

// Safari 17 opened with m,s,p,a and a 10485760 window. It's accepted as an
// older release rather than called a spoof on H2 alone.
func TestSafari17H2StillAccepted(t *testing.T) {
	for _, h2 := range []string{
		"2:0;4:4194304;3:100|10485760|0|m,s,p,a",
		"2:0;4:2097152;3:100|10485760|0|m,s,p,a",
	} {
		fp := realSafari()
		fp.AkamaiH2 = h2
		fp.PseudoOrder = "m,s,p,a"
		if v := Score(fp); hasRule(v, "pseudo-order") || hasRule(v, "h2-vs-ua") {
			t.Errorf("Safari 17 H2 %s must be accepted: %+v", h2, v.Violations)
		}
	}
}

// Accepting two Safari orders must not open the door to Chrome's.
func TestSafariClaimWithChromeH2StillFlagged(t *testing.T) {
	fp := realSafari()
	fp.AkamaiH2 = chromeH2
	fp.PseudoOrder = "m,a,s,p"
	v := Score(fp)
	if !hasRule(v, "pseudo-order") || !hasRule(v, "h2-vs-ua") {
		t.Errorf("Chrome H2 under a Safari UA must trip pseudo-order and h2-vs-ua: %+v", v.Violations)
	}
}

func TestSafariProfileMatchesPublishedSignature(t *testing.T) {
	p, ok := profiles.ByFamily(model.Safari)
	if !ok {
		t.Fatal("no Safari profile")
	}
	if p.PseudoOrder != "m,s,a,p" || p.AkamaiH2 != "2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p" {
		t.Errorf("Safari profile drifted from safari_26.0.1_macOS: %q / %q", p.PseudoOrder, p.AkamaiH2)
	}
}
