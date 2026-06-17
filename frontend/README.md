# Sandboxed — Frontend

A single-file web app (no build step) that drives the [detonation backend](../backend).
Paste or scan a suspicious link → it detonates in the sandbox → you get a verdict,
a screenshot behind "blast glass," the redirect trajectory, and the scored reasons.

## Run it

The backend must be running first (see `../backend`). Then serve this folder over
HTTP (camera/QR needs a real origin, not `file://`):

```bash
cd frontend
# any static server works — examples:
python -m http.server 5500
#   or
npx serve -l 5500
```

Open <http://localhost:5500>.

## Point it at your backend

Top-right **API** field sets the backend URL (saved in your browser).
- Local: `http://localhost:8787` (default)
- Phone demo: paste your `ngrok` URL (run `ngrok http 8787` against the backend).

> For QR camera scanning the page must be served over **https** (or `localhost`).
> ngrok gives you https automatically, which is the easiest way to demo on a phone.

## What's on screen

- **Console** — URL input, Detonate, Scan QR, and sample links.
- **Containment chamber** — the detonated page's screenshot with a SAFE /
  SUSPICIOUS / DANGEROUS verdict stamp.
- **Readout** — final destination, domain age, redirect count, page title,
  the redirect **trajectory**, and the **why** (scored risk reasons).

## Notes

- Pure HTML/CSS/JS — no framework, no bundler. Edit `index.html` and refresh.
- `html5-qrcode` is loaded from a CDN with Subresource Integrity pinned.
- Respects `prefers-reduced-motion` and is responsive down to mobile.
