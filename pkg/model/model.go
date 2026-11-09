package model

type Family string

const (
	Chrome  Family = "chrome"
	Firefox Family = "firefox"
	Safari  Family = "safari"
	Edge    Family = "edge"
	Unknown Family = "unknown"
)

type Fingerprint struct {
	JA4         string   `json:"ja4,omitempty"`
	JA4H        string   `json:"ja4h,omitempty"`
	AkamaiH2    string   `json:"akamai_h2,omitempty"`
	UserAgent   string   `json:"user_agent,omitempty"`
	HTTPVersion string   `json:"http_version,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	PseudoOrder string   `json:"pseudo_order,omitempty"`

	GREASEPresent bool   `json:"grease_present"`
	HasMLKEM      bool   `json:"has_mlkem"`
	HasALPS       bool   `json:"has_alps"`
	SecCHUA       string `json:"sec_ch_ua,omitempty"`
}

type Profile struct {
	Name   string `json:"name"`
	Family Family `json:"family"`

	JA4Prefix string `json:"ja4_prefix"`

	JA4CipherHash string `json:"ja4_cipher_hash"`
	// Other cipher hashes the same browser has shipped. Firefox 154 moved to
	// Chrome's cipher list, so a Firefox profile has to know both the old and
	// the new hash.
	AltCipherHashes []string `json:"alt_ja4_cipher_hashes,omitempty"`
	// Known JA4_c values (sorted extensions + signature algorithms). Only used to
	// tell apart families that share a cipher hash; an unlisted value is normal
	// after a browser update and is not held against the client.
	JA4ExtHashes []string `json:"ja4_ext_hashes,omitempty"`

	AkamaiH2 string `json:"akamai_h2"`
	// Older releases of the same browser that are still in use and send a
	// different HTTP/2 opening. Each is a full Akamai string; its pseudo-header
	// order is accepted alongside PseudoOrder.
	AltAkamaiH2   []string `json:"alt_akamai_h2,omitempty"`
	PseudoOrder   string   `json:"pseudo_order"`
	ExpectsMLKEM  bool     `json:"expects_mlkem"`
	ExpectsALPS   bool     `json:"expects_alps"`
	ExpectsGREASE bool     `json:"expects_grease"`
	UATokens      []string `json:"ua_tokens"`

	// Provenance: when the reference values were captured from a real browser and
	// which versions. Empty CapturedOn means the values are assumed, not measured.
	CapturedOn string `json:"captured_on,omitempty"`
	Versions   string `json:"versions,omitempty"`
}

type BotSignature struct {
	Name        string `json:"name"`
	JA4Prefix   string `json:"ja4_prefix,omitempty"`
	PseudoOrder string `json:"pseudo_order,omitempty"`
	UAToken     string `json:"ua_token,omitempty"`
	Detail      string `json:"detail"`
}

type Severity string

const (
	High   Severity = "high"
	Medium Severity = "medium"
	Low    Severity = "low"
)

type Violation struct {
	Rule     string   `json:"rule"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail"`
}

type Verdict struct {
	Fingerprint    Fingerprint `json:"fingerprint"`
	ClaimedBrowser Family      `json:"claimed_browser"`
	FingerprintFam Family      `json:"fingerprint_family"`
	SpoofScore     int         `json:"spoof_score"`
	Label          string      `json:"label"`
	Violations     []Violation `json:"violations"`
}
