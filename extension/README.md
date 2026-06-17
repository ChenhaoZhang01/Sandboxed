# Sandboxed — Browser Extension

A Chrome/Edge (Manifest V3) extension that checks links in the
[Sandboxed backend](../backend) **before** you visit them — automatically on click,
manually via right-click, or both.

## What it does

- **Check on click** — when enabled, intercepts a link click *before* navigation,
  detonates the URL in the sandbox, and shows a verdict overlay: **safe** links open
  normally; **suspicious/dangerous** links show a warning/block with *Proceed* or
  *Cancel*.
- **Right-click → "Check this link with Sandboxed"** — opens a result window with the
  verdict + screenshot. (Also "Check this page" on the current page.)
- **Toolbar popup** — paste a link, or hit **This tab**, to check on demand. Remembers
  your last input and shows the current mode.
- **Settings** — choose the link-checking mode and the backend URL; persisted across
  browser restarts via `chrome.storage.sync`.

No link ever opens in your real browser during a check — only in the sandboxed headless
browser on the backend.

## Link-checking modes (Settings ⚙)

| Mode | Behavior |
|------|----------|
| **Manual** (default) | Only checks when you right-click → *Check this link*. |
| **On click** | Auto-checks every link before it opens. |
| **Both** | Auto-check on click *and* the right-click option. |

## Install (developer mode)

1. Start the backend: `cd ../backend && npm start` (defaults to `http://localhost:8787`).
2. Open `chrome://extensions` (or `edge://extensions`) → enable **Developer mode**.
3. **Load unpacked** → select this `extension/` folder.
4. Open the extension's **options** (or the popup ⚙) to pick a mode and set the backend URL.

## How it works (architecture)

- `content.js` — runs on every page; in click/both mode it intercepts link clicks and
  shows a **shadow-DOM overlay** (isolated from page CSS) with the verdict.
- `background.js` (service worker) — owns the context menus and is the **single place
  that calls the backend**: the content script sends a `CHECK_URL` message and the
  worker fetches with the extension's host permissions (avoiding page-CSP issues).
- `core.js` — shared settings (`chrome.storage.sync`) + a `detonate()` with timeout and
  friendly error mapping (*Backend unavailable / timed out*); loaded into the worker via
  `importScripts` and into pages via `<script>`.
- `popup` / `result` / `options` — the on-demand UI, the right-click result window, and
  settings.

## Status messages

The UI surfaces clear states: **Checking…**, **Safe**, **Suspicious**, **Dangerous
(blocked)**, and **Backend unavailable** (with a *Proceed anyway* / *Cancel* choice so a
down backend never hard-blocks your browsing).

## Notes & limitations

- Result rendering uses DOM nodes / `textContent` only — a detonated page can't inject
  markup into the extension UI.
- Click interception covers plain left-clicks. Modifier/middle-clicks (open-in-new-tab
  shortcuts) are intentionally left alone; use right-click → *Check this link* for those.
- `host_permissions: ["<all_urls>"]` lets the worker reach whatever backend URL you
  configure; a published build would narrow this to just your backend's origin.
