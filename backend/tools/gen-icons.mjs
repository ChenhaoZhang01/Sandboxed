// One-off: render frontend/icon.svg to PNG app icons using the Puppeteer that
// the backend already has installed. Run from the backend dir: `node tools/gen-icons.mjs`
import puppeteer from "puppeteer";
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const svgPath = resolve(here, "../../frontend/icon.svg");
const outDir = resolve(here, "../../frontend/icons");
mkdirSync(outDir, { recursive: true });
const svg = readFileSync(svgPath, "utf8");

const targets = [
  ["icon-192.png", 192],
  ["icon-512.png", 512],
  ["apple-touch-icon-180.png", 180],
  ["favicon-32.png", 32],
];

const browser = await puppeteer.launch({ headless: true, args: ["--no-sandbox"] });
for (const [name, size] of targets) {
  const page = await browser.newPage();
  await page.setViewport({ width: size, height: size, deviceScaleFactor: 1 });
  const html = `<!doctype html><meta charset="utf8"><style>html,body{margin:0;padding:0}svg{display:block;width:${size}px;height:${size}px}</style>${svg}`;
  await page.setContent(html, { waitUntil: "load" });
  const el = await page.$("svg");
  const buf = await el.screenshot({ type: "png" });
  writeFileSync(resolve(outDir, name), buf);
  await page.close();
  console.log("wrote", name, `${size}x${size}`);
}
await browser.close();
