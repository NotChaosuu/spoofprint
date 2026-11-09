# Changelog

## 1.0.2

- Real Firefox 154+ is no longer scored `spoofed`. Firefox 154 switched to Chrome's exact cipher list, so its JA4 cipher hash (`8daaf6152771`) is Chrome's, and spoofprint used to name the family from that hash alone: every Firefox 154+ visit tripped `ja4-vs-ua` (40 points). When a cipher hash belongs to more than one browser, the family now comes from a known `JA4_c` or the ClientHello's shape (Chromium sends ALPS and GREASE, Firefox sends neither), and is `unknown` if that's still ambiguous. The Firefox profile knows both its old (≤153) and new cipher hashes.
- Safari's HTTP/2 profile now matches real Safari: `2:0;3:100;4:2097152;9:1|10420225|0|m,s,a,p`, pseudo-header order `m,s,a,p` (Safari 18 through 27). Safari 17's older opening (`m,s,p,a`, window 10485760) is still accepted. The values come from curl-impersonate's published Safari signatures; the old ones were assumed and got real Safari 26 flagged on `pseudo-order`.
- Profiles gained optional `alt_ja4_cipher_hashes`, `ja4_ext_hashes` and `alt_akamai_h2` fields; `docs/profiles.example.json` shows them.

## 1.0.1

- `cmd/collector` and `cmd/proxy` were missing from the v1.0.0 tag because `.gitignore` matched the directory names, so `go install …/cmd/collector@latest` failed. The ignore patterns are now anchored to the repo root.
