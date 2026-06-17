// Bundles the Sandboxed PWA (repo `frontend/`) into this Vite site's static output
// so ONE Vercel deployment serves both the landing (/) and the app (/app/).
//
// Runs as the `prebuild` step, so `npm run build` (Vercel's build command) copies
// the latest frontend into public/app before Vite builds. The PWA is fully relative
// (manifest + service worker use "./" paths), so it works unchanged under /app/.
//
// public/app is gitignored — it's a generated copy, never edited here.

import { cpSync, rmSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url)); // website/landing/scripts
const landingRoot = resolve(here, "..");              // website/landing
const repoRoot = resolve(landingRoot, "..", "..");    // repo root
const src = join(repoRoot, "frontend");
const dest = join(landingRoot, "public", "app");

if (!existsSync(src)) {
  console.error(`[copy-app] frontend not found at ${src} — skipping (build will lack /app).`);
  process.exit(0); // don't fail the whole build
}

rmSync(dest, { recursive: true, force: true });
mkdirSync(dest, { recursive: true });
cpSync(src, dest, { recursive: true });

console.log(`[copy-app] copied PWA: ${src} -> ${dest}`);
