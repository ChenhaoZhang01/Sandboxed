# Sandboxed Phone Scanner

This folder is the shared phone experience for iPhone and Android. It is a
mobile-first PWA, not a native app: open it in Safari or Chrome, allow camera
access, and it scans QR codes without opening the link on the phone.

The UI intentionally mirrors the main frontend and extension: same colors,
stylesheet, console panel, containment chamber, cyan verdict stamp, scan
options, QR scanner, PDF section, replay/live controls, trajectory, and scored
reasons. Keep `phones/index.html`, `phones/app.js`, and `phones/styles.css`
close to the frontend versions; phone-only changes should stay small.

## Why this works for both platforms

- iPhone: Safari supports camera access for HTTPS or localhost pages.
- Android: Chrome supports camera access and usually installs the PWA cleanly.
- Android browsers that support Web Share Target can share links into this app.
  iOS may ignore that manifest field, so paste and camera scan remain the common
  path on both platforms.

Native App Store and Play Store builds can wrap this later with Capacitor, but
the hackathon demo should use the PWA because it is one code path.

## Run locally

Start the backend first, then serve this folder:

```bash
cd phones
python -m http.server 5600
```

Open `http://localhost:5600`. For real phones, expose both frontend and backend
over HTTPS, for example with ngrok, because camera access requires a secure
origin outside localhost.
