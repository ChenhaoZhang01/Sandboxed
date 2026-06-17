# Sandboxed — URL Detonation Engine

The backend for **Sandboxed**: it "detonates" a suspicious URL (the kind
hidden behind a scammy QR code) inside a sandboxed headless browser, follows the
full redirect chain, screenshots the real landing page, and returns a risk
verdict — **without the link ever touching the user's device.**

## What it does

`POST /detonate { "url": "..." }` →

1. Opens the URL in an **isolated incognito browser context** (clean cookies/storage).
2. **Unwraps the redirect chain** (e.g. `bit.ly → sketchy.ru → fake-paypal.com`).
3. **Screenshots** the landing page (base64 JPEG).
4. Extracts **behavioral signals**: password fields, payment fields, cross-domain
   credential POSTs, brand impersonation, auto-downloads, meta-refresh, insecure HTTP.
5. Adds **runtime threat instrumentation** for clipboard hooks, `eval`/Function usage,
   keystroke listeners, pop-under/window-open behavior, crypto-wallet provider hooks
   (`window.ethereum` / `window.solana`), typosquat lookalikes, and TLS/certificate checks.
6. Enriches with **domain age** (RDAP, free, no key) and optional **Google Safe Browsing**.
6. Returns a **verdict** (`safe` / `suspicious` / `dangerous`) + scored reasons + screenshot.

## Run it (local dev)

```bash
cd backend
npm install                 # downloads Chromium on first install
cp .env.example .env        # optional; works with zero keys
npm start                   # http://localhost:8787
```

Detonate a URL:

```bash
curl -s -X POST http://localhost:8787/detonate \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

Run the full automated tests (credential detection + new runtime/TLS/typosquat coverage):

```bash
npm test
```

Run the offline phishing-fixture test (proves the credential-detection path):

```bash
npm run test:local
# => verdict: dangerous | score: 105  (fake PayPal login form)
```

## Connect a phone for the demo

Run the backend on your laptop, expose it with [ngrok](https://ngrok.com), and
point the mobile scanner at the public URL:

```bash
ngrok http 8787
```

## Run in Docker (the "sandbox" isolation story)

```bash
docker build -t sandboxed .
docker run -p 8787:8787 sandboxed
```

Each container is a disposable sandbox. In production you'd spin one ephemeral
container (or Firecracker microVM via Fly.io Machines / Cloudflare) **per scan**
and destroy it after — that's the hardening path; the single shared instance is
fine for the hackathon demo.

## Response shape

```jsonc
{
  "verdict": "dangerous",
  "score": 105,
  "reasons": [{ "points": 30, "reason": "Page impersonates \"paypal\" but domain is ..." }],
  "finalUrl": "https://...",
  "redirectChain": ["http://...", "https://..."],
  "redirectCount": 1,
  "signals": { "passwordFields": 1, "crossDomainCredPost": true, "...": "..." },
  "intel": { "domainAge": { "ageDays": 3 }, "safeBrowsing": { "skipped": true } },
  "screenshotBase64": "/9j/4AAQ...",
  "elapsedMs": 2535
}
```

## Config (`.env`, all optional)

| Var | Default | Purpose |
|-----|---------|---------|
| `PORT` | `8787` | Server port |
| `SAFE_BROWSING_API_KEY` | — | [Google Safe Browsing](https://developers.google.com/safe-browsing) (free). Skipped if unset. |
| `DETONATE_TIMEOUT_MS` | `15000` | Max navigation time per detonation |
| `MAX_REDIRECTS` | `15` | Abort runaway redirect loops |

## Safety notes

- **SSRF guard** (`src/ssrf.js`): every target is DNS-resolved and rejected if any
  resolved address is non-public (loopback, private, link-local incl. cloud
  metadata `169.254.169.254`, unique-local, reserved). IP forms are canonicalized
  via the WHATWG URL parser, so octal/hex/decimal (`http://2130706433`) and IPv6 /
  IPv4-mapped bypasses are closed. The check is re-applied to **every redirect hop**
  inside the engine, not just the initial URL.
  - Residual risk: a narrow DNS-rebinding TOCTOU window remains between our lookup
    and Chromium's connect. To fully close it, pin the resolved IP and connect to it
    directly (left as hardening).
  - `ALLOW_PRIVATE_TARGETS=1` disables the guard — **test-only**, never in deploy.
- File downloads are **denied** (never written to disk) — only the *intent* is recorded.
- Pages run in headless Chromium with `--no-sandbox` for portability; for real
  isolation, run one container/microVM per scan as described above.
