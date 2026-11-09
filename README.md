# spoofprint

A bot can put `Chrome/151` in its User-Agent in one line. Lining up the TLS handshake and HTTP/2 frames its network stack actually sends is harder — a stock scraper (requests, httpx, plain Go) gives itself away immediately. spoofprint sits in front of your service, reads that wire fingerprint, and scores whether the TLS layer, the HTTP/2 layer, and the User-Agent all tell the *same* story. When they don't, the client is very likely spoofing.

It's a signal, not a silver bullet. It doesn't chase one golden fingerprint — a dedicated impersonation stack (curl_cffi, tls-client) that faithfully reproduces a current browser across every layer will, correctly, score `consistent`; there's nothing inconsistent to catch. What spoofprint catches is the large majority of automation that doesn't get every layer right at once, and it explains exactly which layer gave it away.

```
# a scraper sending a Chrome User-Agent over a Go/curl TLS stack:
{
  "claimed_browser": "chrome",
  "fingerprint_family": "unknown",
  "spoof_score": 100,
  "label": "spoofed",
  "violations": [
    { "rule": "no-grease",           "severity": "high",   "detail": "Claims Chrome but the TLS ClientHello contains no GREASE values; a real Chrome injects GREASE." },
    { "rule": "pseudo-order",        "severity": "high",   "detail": "HTTP/2 pseudo-header order a,m,p,s does not match Chrome's (m,a,s,p)." },
    { "rule": "missing-pq-keyshare", "severity": "medium", "detail": "Claims Chrome but the ClientHello lacks the X25519MLKEM768 post-quantum key share that current Chrome sends." }
  ]
}
```

A real Chrome hitting the same endpoint comes back `"label": "consistent"`, `"spoof_score": 0`, no violations.

## The strongest tell in 2026

Current Chrome (131+), Firefox (132+), and Safari 26 all send a post-quantum key share — `X25519MLKEM768` — in their TLS ClientHello; on Cloudflare's own numbers that's over half of human HTTPS traffic (Oct 2025). Stock scraping libraries don't send it, so a request claiming to be a current browser without that key share is a cheap, high-signal tell. Know the ceiling, though: a dedicated impersonation library like curl_cffi *does* send it now — so this check catches the common naive stack, not a determined impersonator. That's what the cross-layer consistency scoring is for.

## Install

```bash
go install github.com/NotChaosuu/spoofprint/cmd/collector@latest
go install github.com/NotChaosuu/spoofprint/cmd/proxy@latest
```

Go 1.22+. Only dependency is `golang.org/x/net` for the HTTP/2 framer.

## Two ways to run it

**collector** — a standalone TLS server that fingerprints whatever connects and returns the verdict as JSON. Point a browser or an HTTP client at it and see what you look like.

```bash
collector -addr :8443
curl -k https://localhost:8443/          # returns the verdict for curl's own fingerprint
```

**proxy** — a TLS-terminating reverse proxy. It scores every request, injects `X-Spoofprint-Score`, `X-Spoofprint-Label`, and `X-Spoofprint-JA4` for your upstream to act on, and can block outright.

```bash
proxy -addr :8443 -upstream http://127.0.0.1:3000
proxy -addr :8443 -upstream http://127.0.0.1:3000 -block 40   # 403 anything scoring >= 40
```

Both self-sign a certificate if you don't pass `-cert`/`-key` (pass both or neither — passing only one is an error).

**One real difference between the two:** the proxy sits on Go's `net/http` server, which hands you parsed requests, not raw HTTP/2 frames. So the proxy scores the TLS-layer checks (JA4-vs-UA, GREASE, PQ key-share, ALPS, sec-ch-ua) but **not** the HTTP/2 frame checks (`h2-vs-ua`, `pseudo-order`). The collector reads the raw frames itself and runs all of them — the example verdict above, with its `pseudo-order` violation, comes from the collector. Use the collector when you want the full picture; use the proxy to gate on the TLS-layer signals inline.

## Keeping profiles current

The browser reference values are the one thing that goes stale — a new Chrome release can shift an HTTP/2 SETTING. You don't need a new binary to fix that:

```bash
collector -dump ./caps                     # capture real browsers into ./caps
# turn a capture into a profile JSON (see docs/profiles.example.json for the shape)
collector -profiles ./profiles.json        # override the built-ins at runtime
```

Each profile carries a `captured_on` date and the versions it came from. On startup spoofprint warns for any profile older than six months or whose values weren't captured by spoofprint itself (Safari, today) — so a surprising verdict has a visible cause instead of a silent one. `-profiles` merges by family: an entry replaces the built-in of the same browser, and a new family is added. An override replaces the whole entry, so a Firefox override needs both of Firefox's cipher hashes (`ja4_cipher_hash` plus `alt_ja4_cipher_hashes`) or Firefox 154+ goes back to looking like Chrome.

## What it checks

Every request that claims to be a browser is scored across a handful of rules:

- **JA4 vs User-Agent** — the browser family implied by the TLS fingerprint doesn't match the one the UA claims. (An unrecognized UA whose JA4 *matches* a real browser is treated as corroboration, not a violation — so genuine iOS Chrome and in-app webviews aren't punished for a UA the parser doesn't know.)
- **Unreadable ClientHello** — a request that claims a browser over TLS but whose handshake produced no parseable ClientHello (a deliberately fragmented or malformed hello) **fails closed**. Not being able to read the fingerprint costs points; it doesn't earn a pass.
- **HTTP/2 vs User-Agent** — the SETTINGS block *and the connection window* and pseudo-header order don't match the claimed browser. SETTINGS are compared leniently (only values the profile declares, to survive browser drift); the connection window is a high-signal, stable value and is compared when both sides send one.
- **No GREASE** — the ClientHello carries no GREASE values, which a real Chrome/Edge/Safari always injects (Firefox is the exception, and spoofprint knows that).
- **HTTP/1.1 only** — claims a modern browser but never negotiated HTTP/2.
- **Missing post-quantum key share** — the X25519MLKEM768 tell above.
- **Missing ALPS** — claims a Chromium browser but omits the `application_settings` extension every Chromium sends.
- **sec-ch-ua vs User-Agent** — the client hints disagree with the UA version.
- **Known non-browser fingerprint** — the wire fingerprint matches a stock stack (Go `net/http`, curl, python-requests, ...) behind a browser UA.

Violations are weighted into a 0–100 score and a label: `consistent`, `suspicious`, `spoofed`, or `not-a-browser-claim` (an honest curl declaring itself isn't lying, so it isn't punished).

## Two design decisions worth knowing

**JA3 is dead for Chrome.** Chrome varies its ClientHello between connections — the extension order is shuffled, and the extension *set* itself shifts (16 vs 17 extensions on the same build). That moves a classic JA3 hash every connection. JA4 sorts the extension list before hashing, so the shuffling alone wouldn't matter — but the varying set still moves both the JA4_a prefix and the JA4_c extension hash. The cipher list doesn't move, so spoofprint starts from the **JA4 cipher hash** (`JA4_b`); matching on the full JA4 prefix would miss real Chrome. The cipher hash isn't unique, though: since Firefox 154, Firefox sends exactly Chrome's 15 ciphers, so both come out as `t13d1517h2_8daaf6152771_…`. When a cipher hash belongs to more than one browser, spoofprint looks at the extensions: a known `JA4_c` settles it, and otherwise the ClientHello's shape does (Chromium sends ALPS and GREASE, Firefox sends neither). If that still doesn't single out one browser, the family is reported as `unknown` and the JA4-vs-UA rule stays quiet rather than guessing.

**The HTTP/2 priority field is noisy.** Real Chrome varies the PRIORITY weight it sends from one connection to the next, so the comparison comes down to the stable parts — SETTINGS, connection window, and pseudo-header order — and ignores the priority field. Both of these came out of comparing the profiles against real captured browser traffic; the browser profiles ship with a capture script (`scripts/capture.ps1`) so you can regenerate them.

## Where it's honest about its limits

- **Profiles are per-browser reference values, and browsers drift.** Chrome, Edge and Firefox are from real captures; Safari doesn't run on Windows, where those were taken, so its values come from curl-impersonate's published Safari signatures (Safari 26.0.1 on macOS; 18 through 27 open HTTP/2 the same way, and Safari 17's older opening is also accepted). Until Safari is captured here, the stricter missing-value HTTP/2 checks stay off for it. Because HTTP/2 SETTINGS shift between browser releases, the scorer compares only the settings a profile actually declares and tolerates extras — a single drift lands a `medium`, not an auto-`spoofed`. Keeping the profiles current is the maintenance cost of this approach — but it's now a config change, not a release: `-profiles` swaps in a fresh capture at runtime, and a startup warning flags any profile that's stale or assumed, so a stale profile announces itself instead of quietly mislabeling.
- **A dedicated impersonation library scores `consistent`.** curl_cffi/tls-client faithfully reproducing a current browser is, by definition, consistent across the layers spoofprint checks — it will pass. This tool raises the floor (catches stock automation and half-built impersonations) rather than defeating a determined one; run it as one signal among several, not a sole gate.
- **HTTP/3 / QUIC isn't scored yet.** That's the next version; roughly a fifth of traffic is H3 today, and the same fingerprint ideas carry over.
- It scores TLS + HTTP/2 consistency, not behavior. A `consistent` verdict means the layers agree, not that the client is friendly.

As far as I can tell there's no other open-source tool that scores TLS-vs-User-Agent consistency this way — the closest, [Finch](https://github.com/0x4D31/finch), blocks and tarpits on fingerprints but doesn't score and explain the mismatch.

## Roadmap

The current checks score a *snapshot* — the ClientHello and the opening HTTP/2 frames. A faithful impersonation library replays that snapshot byte-for-byte, which is why it scores `consistent`. The way past that is to score signals a replayer can't copy because it has no real network stack behind it:

- **Active flow-control probing** — advertise a small `SETTINGS_INITIAL_WINDOW_SIZE` and watch *when* the client emits `WINDOW_UPDATE`. A frame replayer has no state machine to drive it; a real browser does.
- **HelloRetryRequest** — force one and check which group the client retries with. Snapshot impersonators commonly get this wrong.
- **Self-maintaining profiles in CI** — the runtime pieces exist today (`captured_on` provenance, a startup staleness warning, and `-profiles` to swap in a fresh capture without a rebuild). The remaining piece is a CI job that re-captures against real browsers on a schedule and reddens the build when reality drifts, so staleness is caught by the pipeline rather than by a user's surprising verdict.
- **HTTP/3 / QUIC** — roughly a fifth of traffic; JA4 already specifies the `q` variant.

These flip the economics: instead of copying bytes once, an evader has to emulate behaviour. That's the direction, not a claim about today.

## License

MIT

## Author

Chaosuu — t.me/chaosuudev. 
