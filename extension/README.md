# Sandboxer — Browser Extension

A Chrome/Edge (Manifest V3) extension that detonates links in the
[Sandboxer backend](../backend) right from the browser — so you can check a
link **before** you click it.

## What it does

- **Right-click a link → "Detonate link in Sandboxer"** — opens a result window
  that detonates the link in the sandbox and shows the verdict + screenshot.
- **Right-click a page → "Detonate this page in Sandboxer"** — same, for the
  current page URL.
- **Toolbar popup** — paste a link, or hit **This tab** to detonate the page
  you're on.
- **Options** — set the backend ("detonation engine") URL.

It talks to the same `POST /detonate` API as the web app; no link is ever opened
in your real browser — only in the sandboxed headless browser on the backend.

## Install (developer mode)

1. Start the backend: `cd ../backend && npm start` (defaults to `http://localhost:8787`).
2. Open `chrome://extensions` (or `edge://extensions`).
3. Turn on **Developer mode** (top-right).
4. Click **Load unpacked** and select this `extension/` folder.
5. Pin the Sandboxer icon, then click it (or right-click any link).

## Configure the backend URL

Click the ⚙ in the popup (or the extension's **Details → Extension options**):
- Local dev: `http://localhost:8787`
- Remote: your tunnel/deploy URL (e.g. an `https` ngrok address).

> The extension requests `host_permissions: ["<all_urls>"]` so it can `fetch`
> whatever backend URL you configure. For a published build you'd narrow this to
> just your backend's origin.

## Files

| File | Role |
|------|------|
| `manifest.json` | MV3 manifest (permissions, action, options, background) |
| `background.js` | Service worker — context-menu items, opens the result window |
| `core.js` | Shared API client + result renderer (DOM-built, no `innerHTML`) |
| `popup.html` / `popup.js` | Toolbar popup |
| `result.html` / `result.js` | Detonation result window (from right-click) |
| `options.html` / `options.js` | Backend URL setting |
| `ui.css` | Shared "containment chamber" styling |
| `icons/` | Toolbar / store icons |

## Notes

- Result rendering uses `textContent` / DOM nodes only — untrusted content from a
  detonated page can't inject markup into the extension UI.
- The backend URL is stored in `chrome.storage.sync`.
