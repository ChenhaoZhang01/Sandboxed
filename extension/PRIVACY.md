# Privacy Policy — Sandboxed (Link Detonator)

_Last updated: 2026-06-17_

Sandboxed is a browser extension that checks links in a sandbox before you visit
them and shows you a risk verdict. This policy explains exactly what the
extension does and does not do with your data.

## What the extension sends

When you ask Sandboxed to check a link — by right-clicking it, or by clicking a
link while click-protection is enabled — the extension sends **only that single
URL** to the analysis backend you have configured in the extension's options
(the "API base", which defaults to a server you run yourself).

That URL is used solely to load the page in a disposable, isolated browser on the
backend and return a risk verdict (safe / suspicious / dangerous) and related
findings (redirect chain, screenshot, detected signals) back to you.

## What the extension does NOT do

- It does **not** collect, store, or transmit your browsing history.
- It does **not** track the pages you visit. The content script only acts when
  you explicitly trigger a check (right-click) or when you have turned on
  click-protection, and even then it sends only the one link you acted on.
- It does **not** sell or share any data with third parties.
- It does **not** use analytics, advertising, or tracking SDKs.
- It does **not** read or transmit the contents of pages you browse.

## Data storage

The only data the extension stores is your own settings — the backend API base
URL and your chosen check mode — saved via Chrome's `storage.sync` so they
persist across your signed-in browsers. Settings never leave Google's sync
storage except to be applied locally in the extension.

## The analysis backend

The link you submit is processed by the backend at the API base you configure.
By default this uses the hosted backend at `https://sandboxed.fly.dev`, so the
extension is ready to use out of the box. If you point the extension at your own
backend, the submitted URL is processed there per that server's own policy. The
backend does not require any account, login, or personal information.

## Permissions and why they are needed

- **contextMenus** — to add the "Check this link with Sandboxed" right-click item.
- **storage** — to save your settings (API base, check mode).
- **tabs** — to open the verdict/result page and identify the active page's URL.
- **host access (`<all_urls>`)** — so the content script can offer click-checking
  on any site and send the single link you act on to your configured backend.
  No page content is read or transmitted.

## Contact

Questions about this policy: chenhaozhang01@gmail.com
