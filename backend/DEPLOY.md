# Deploying the Sandboxed backend to Render

The backend runs a real headless Chromium (Puppeteer), so it needs a long-running
container — not a serverless function. It ships a Dockerfile and a Render Blueprint
(`render.yaml` at the repo root), so you can deploy it straight from GitHub.

## Deploy from Git (Blueprint — recommended)
1. Push this repo to GitHub (already connected as the `main` branch).
2. Go to https://dashboard.render.com → **New + → Blueprint**.
3. **Connect your Git provider** (GitHub/GitLab) and pick this repo.
   - First time: click **Configure account** / **Connect GitHub**, authorize Render,
     and grant access to this repo. It then appears in the repo list.
4. Render detects `render.yaml` and shows the **sandboxed-backend** web service.
   Click **Apply** / **Create**.
5. First build takes a few minutes (it pulls the Puppeteer image + `npm ci`).
   When it's live you get a URL like `https://sandboxed-backend.onrender.com`.

### Manual alternative (no Blueprint)
**New + → Web Service** → connect repo → set:
- **Root Directory:** `backend`
- **Runtime:** Docker (auto-detected from the Dockerfile)
- **Health Check Path:** `/health`
- **Instance Type:** Free

## After it's live
- Test it: open `https://<your-service>.onrender.com/health` → `{"ok":true,"service":"sandboxed"}`.
- Point the clients at the URL:
  - **Extension:** Options → API base.
  - **PWA:** the in-app API setting (`sandboxed_api`).
- **CORS:** `cors()` is currently open to all origins (`src/server.js`). Once the PWA
  has a fixed origin, restrict it: `app.use(cors({ origin: "https://your-pwa" }))`.

## Notes / gotchas
- **Free tier sleeps after ~15 min idle** → the next request cold-starts in 30–60s.
  Before a live demo, hit `/health` once to warm it up.
- **Free tier is 512 MB RAM.** Chromium is already launched with `--no-sandbox` and
  `--disable-dev-shm-usage` (`src/detonate.js`), which is what containers need, but a
  very heavy page could still OOM. If you see crashes, upgrade the instance type in
  `render.yaml` (`plan: starter`) or in the dashboard.
- **Never set `ALLOW_PRIVATE_TARGETS`** in production — it's a test-only escape hatch
  that disables the SSRF protections in `src/ssrf.js`.
