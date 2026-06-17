# Deploying the Sandboxed landing page to Vercel

This site lives in the `landing/` folder of the repo (separate from the Sandboxed
app). Because the repo has multiple projects, the one thing that matters is telling
Vercel that this site's **Root Directory is `website/landing`**.

## Option A — Vercel dashboard (easiest, no terminal)
1. Go to https://vercel.com → **Add New… → Project** → import this GitHub repo.
2. On the configure screen, set **Root Directory** to `website/landing`.
3. Framework should auto-detect as **Vite**. Leave the rest as-is
   (Build Command `npm run build`, Output Directory `dist` — already in `vercel.json`).
4. Click **Deploy**. You'll get a live URL in ~1 minute.
5. Every push to GitHub re-deploys automatically.

## Option B — Vercel CLI (from the terminal)
```bash
cd website/landing
npx vercel          # first run: log in + link the project (answer the prompts)
npx vercel --prod   # publish to your production URL
```
Run these from inside the `landing/` folder so Vercel treats it as the project root.

## After it's live
- Point the two **"Try Sandboxed"** call-to-action links at the real app URL.
  They're marked `data-cta` in `index.html` (currently `href="#"`); update the
  `href`, or wire the TODO in `src/main.js`.
- The 3 background images are copies in `landing/public/images/`. If you change
  the originals in the repo's top-level `/images`, re-copy them here.
