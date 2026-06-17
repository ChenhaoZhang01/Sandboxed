# Chrome Web Store submission pack

Use this as the draft pack for the Chrome Web Store submission and review notes.

## 1. Store listing summary
Title: Sandboxed — Link Detonator

Short description:
Check suspicious links in a disposable sandbox before you visit them. Sandboxed runs a remote detonation backend to show a safer verdict, screenshot, and redirect trail.

Detailed description:
Sandboxed helps you inspect suspicious links before opening them in your real browser. The extension can:
- check a link on click or on demand,
- show a risk verdict and screenshot from a disposable detonation session,
- follow redirects and reveal the final destination,
- let you choose a backend URL that matches your trust model.

This extension uses a remote backend because the detonation flow relies on a headless browser, redirect handling, and phishing-enrichment checks that are heavier and more fragile to run entirely inside the extension. Keeping that work on a backend avoids overloading the browser process and makes it easier to keep the sandbox logic isolated from your normal browsing session.

## 2. Permissions and why they are needed
- contextMenus
  - Needed to add the right-click menu item “Check this link with Sandboxed”.
- storage
  - Needed to persist the user’s backend URL and preferred mode across browser restarts.
- tabs
  - Needed to support “This tab” analysis and result windows that open with the current tab context.
- host_permissions: <all_urls>
  - Needed because the extension lets the user choose any URL to analyze and the backend fetches that URL for detonation. The permission is scoped to the backend request path and the user-selected URL analysis flow.

## 3. Why the extension uses a remote backend
The extension does not try to do everything locally. It uses a remote backend because the core detonation path runs a disposable headless browser session, follows redirects, captures screenshots, and can apply phishing-enrichment checks. Those tasks are better handled outside the extension process for reliability, security isolation, and to keep the browser extension lightweight.

The backend is optional and user-configurable. The extension supports local development and a hosted backend so the user can choose the deployment model they trust.

## 4. Privacy and legal URLs
Replace the placeholders below with the real live URLs after deploying the landing page.
- Website: https://<your-live-landing-url>
- Privacy policy: https://<your-live-landing-url>/privacy-policy.html
- Terms of service: https://<your-live-landing-url>/terms-of-service.html
- Support: https://<your-live-landing-url>

## 5. Review notes for Chrome Web Store
- The extension is a security and safety tool, not an adware or tracking extension.
- It does not collect browsing history by default.
- It only analyzes the URL the user explicitly chooses to inspect.
- The backend and the extension are designed to keep the actual browsing session separate from the detonation path.

## 6. Suggested screenshots
Use the existing extension popup and result flow screenshots from your review build. If you need a new set, capture:
1. popup with a pasted URL,
2. result window showing verdict + screenshot,
3. options page with backend URL and mode picker.
