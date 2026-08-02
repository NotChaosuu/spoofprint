# Live-capture reconciliation — 2026-07-29

Captured real ClientHello + HTTP/2 flights from browsers installed on the build
machine via `scripts/capture.ps1` (collector `-dump` mode). Raw ClientHello hex
saved in each capture. Browsers: Chrome 149, Edge 150, Brave 150, Firefox 151.
Safari could not be captured (Windows). Files under `testdata/captures/`.

## Ground-truth fingerprints

### Chromium (Chrome 149 / Edge 150 / Brave 150 — identical wire, as expected)
- JA4 cipher hash (part B): **`8daaf6152771`** — stable across all three, all connections.
- JA4 part-A: **varies `t13d1516h2` ↔ `t13d1517h2`** (16 vs 17 extensions after GREASE strip). The extra extension is Chrome's size-driven padding, not always present.
- Ciphers (16 w/ GREASE, 15 after strip): `4a4a 1301 1302 1303 c02b c02f c02c c030 cca9 cca8 c013 c014 009c 009d 002f 0035`
- GREASE: **present** (cipher `4a4a`, exts `dada`/`7a7a`).
- ALPS: **present** (ext `44cd` = ALPS v2). MLKEM: present. ECH ext `fe0d` present.
- Akamai H2: `1:65536;2:0;4:6291456;6:262144|15663105|<priority>|m,a,s,p`
  - SETTINGS + WINDOW_UPDATE (15663105) + pseudo (`m,a,s,p`) **stable**.
  - **PRIORITY field varies** per connection: `1:1:0:256`, `1:1:0:220` — headless Chrome sends a HEADERS priority with a variable weight. NOT `0` as the profile assumed.

### Firefox 151.0.3 (TLS-only — rejects self-signed cert, so no H2 captured)
- JA4: **`t13d1617h2_86a278354501_3cbfd9057e0d`** (16 ciphers, 17 exts, cipher hash `86a278354501`).
- Ciphers (16): `1301 1303 1302 c02b c02f cca9 cca8 c02c c030 c00a c013 c014 009c 009d 002f 0035`
- **GREASE: ABSENT.** Firefox 151 sends no GREASE in ciphers or extensions.
- ALPS: absent (correct — Chromium-only). MLKEM: present. ECH ext `fe0d` present.

## Bugs this caught (all would flag REAL browsers as spoofed)

1. **`no-grease` rule false-positives Firefox.** Firefox sends no GREASE, so the blanket "browser without GREASE = spoofed" (High) fires on every real Firefox. FIX: gate on a per-profile `ExpectsGREASE` (Chrome/Edge/Safari true, Firefox false).

2. **JA4 part-A prefix match collides Chrome↔Safari.** Chrome emits `t13d1517h2` on ~half its connections; that's exactly the Safari profile prefix. Real 17-ext Chrome → identified as Safari → `ja4-vs-ua` (High) fires. FIX: match family by the JA4 **cipher hash** (part B, `8daaf6152771` etc.), which is stable and permutation-immune. Ext count is not identity.

3. **Akamai H2 exact-match fails on real Chrome.** The PRIORITY field varies (`1:1:0:256`/`:220`); the profile expects `0`. Exact string compare → `h2-vs-ua` (High) fires on real Chrome. FIX: compare SETTINGS + WINDOW_UPDATE + pseudo-order; exclude the PRIORITY field from the match.

4. **Firefox profile JA4 was wrong.** Assumed `t13d1715h2` / cipher hash `5b57614c22b0`; real is `t13d1617h2` / `86a278354501`. FIX: profile updated to captured values.

## Still unverified (needs a real capture someday)
- **Safari** everything (can't run on Windows). Cipher hash `a09f3c656075`, H2 string, pseudo `m,s,p,a`, INITIAL_WINDOW_SIZE, ExpectsGREASE=true are all assumed. Capture on a Mac/iPhone or BrowserStack before trusting Safari verdicts. Until then Safari fails open (unmatched cipher hash → Unknown → no false-positive, just no positive ID).
