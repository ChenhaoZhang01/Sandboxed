import puppeteer from "puppeteer-extra";
import StealthPlugin from "puppeteer-extra-plugin-stealth";

puppeteer.use(StealthPlugin());

// Container runtimes (Fly, Render, Docker) need these flags or Chrome's
// sandbox fails to init and the launch hangs/crashes. Mirrors detonate.js.
const SEARCH_LAUNCH_ARGS = [
  "--no-sandbox",
  "--disable-setuid-sandbox",
  "--disable-dev-shm-usage",
  "--disable-gpu",
];
if (process.env.CHROME_SINGLE_PROCESS === "1") {
  SEARCH_LAUNCH_ARGS.push("--no-zygote", "--single-process");
}

const SEARCH_TIMEOUT_MS = Number(process.env.BRAND_SEARCH_TIMEOUT_MS || 10000);

export async function findRealSiteViaBrowser(query) {
  // Enrichment only — never let a failed/slow search hang or crash a detonation.
  let browser = null;
  let results = [];
  try {
    browser = await puppeteer.launch({ headless: true, args: SEARCH_LAUNCH_ARGS });
    const page = await browser.newPage();

    await page.setUserAgent(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    );

    await page.goto(`https://www.bing.com/search?q=${encodeURIComponent(query)}`, {
      waitUntil: "domcontentloaded",
      timeout: SEARCH_TIMEOUT_MS,
    });

    results = await page.evaluate(() => {
      const anchors = [...document.querySelectorAll("#b_results .b_algo h2 a")];
      return anchors.slice(0, 5).map(a => a.href);
    });
  } catch (err) {
    console.error("brand search failed (non-fatal):", err.message || err);
    return [];
  } finally {
    if (browser) await browser.close().catch(() => {});
  }

  return results.map(href => {
    try {
      const u = new URL(href).searchParams.get("u");
      const realUrl = u ? decodeURIComponent(atob(u.replace(/^a1/, ""))) : href;
      let domain = new URL(realUrl).hostname;
      // Strip markdown formatting if present: [www.foo.com](https://www.foo.com) → www.foo.com
      const mdMatch = domain.match(/^\[([^\]]+)\]/);
      if (mdMatch) domain = mdMatch[1];
      return { url: realUrl, domain };
    } catch {
      return null;
    }
  }).filter(Boolean);
}