import puppeteer from "puppeteer-extra";
import StealthPlugin from "puppeteer-extra-plugin-stealth";

puppeteer.use(StealthPlugin());

export async function findRealSiteViaBrowser(query) {
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();

  await page.setUserAgent(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
  );

  await page.goto(`https://www.bing.com/search?q=${encodeURIComponent(query)}`, {
    waitUntil: "networkidle2",
  });

  const results = await page.evaluate(() => {
    const anchors = [...document.querySelectorAll("#b_results .b_algo h2 a")];
    return anchors.slice(0, 5).map(a => a.href);
  });

  await browser.close();

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