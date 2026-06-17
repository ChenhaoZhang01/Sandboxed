# Deploying the Sandboxed backend

The backend runs a real headless Chromium (Puppeteer), so it needs a long-running
container — not a serverless function. It ships a Dockerfile and works on any
container host. **Railway is the recommended host** (no idle-sleep / cold starts,
more RAM than Render's free tier). Render instructions follow as an alternative.

---

# Railway (recommended)

Railway has no cold starts and gives the container enough memory for Chromium, so
detonations don't time out. It builds from the same Dockerfile via `railway.json`.

## Deploy from Git
1. Push this repo to GitHub.
2. https://railway.app → **New Project → Deploy from GitHub repo** → pick this repo.
3. Open the service → **Settings → Source → Root Directory = `backend`**.
   (Railway then reads `backend/railway.json` + `backend/Dockerfile`.)
4. **REQUIRED — Variables tab → add `CHROME_SINGLE_PROCESS` = `1`.** Railway's
   container runtime blocks the syscalls Chrome's zygote uses, so without this the
   detonation crashes at `sandbox/credentials.cc` even though `/health` works. This
   flag makes Chrome run single-process to avoid that path.
5. **Settings → Networking → Generate Domain** to get a public URL like
   `https://sandboxed-backend-production.up.railway.app`.
6. First build pulls the Puppeteer image + `npm ci` (a few minutes). Railway injects
   `PORT` automatically; `src/server.js` already reads it.

## After it's live
- Test: `https://<your-domain>/health` → `{"ok":true,"service":"sandboxed"}`, then POST
  a detonate (see curl below).
- Point the clients at the Railway domain: extension Options → API base, and the PWA's
  API field / the `DEFAULT_API` in `frontend/app.js`.

---

# Fly.io (backup — most stable Chrome)

Use this if Railway's `--single-process` Chrome proves flaky on heavy pages. Fly runs
Firecracker microVMs with a real kernel, so Chrome's sandbox works and it runs full
multi-process — **do NOT set `CHROME_SINGLE_PROCESS` here.** Config is `backend/fly.toml`.

1. Install the CLI: `iwr https://fly.io/install.ps1 -useb | iex` (Windows) and `fly auth login`.
2. From the `backend/` folder: `fly launch --no-deploy` (creates the app from `fly.toml`;
   pick a unique app name if `sandboxed-backend` is taken).
3. `fly deploy` — builds the Dockerfile and ships it. You get `https://<app>.fly.dev`.
4. Test `/health` then a `/detonate` curl, and point the clients at the `.fly.dev` URL.

---

# Render (alternative)

It ships a Render Blueprint (`render.yaml` at the repo root), so you can deploy it
straight from GitHub. NOTE: Render's free tier sleeps after ~15 min idle and is
capped at 512 MB RAM, which can make detonations slow or time out.

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
