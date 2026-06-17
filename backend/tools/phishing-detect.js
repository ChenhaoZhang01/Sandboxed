// phishing-detect.js
import { compareFavicons } from "./favicon-compare.js";
import { findRealSiteViaBrowser } from "./brand-search.js";

export async function checkForPhishing(report) {
    const { finalUrl, title, h1s, favicon, signals } = report;
    const finalHost = signals?.finalHost ?? new URL(finalUrl).hostname.replace(/^www\./, "");
  const query = title || h1s[0];
  if (!query) return null;

  console.log("searching for:", query, "and hostname:", new URL(finalUrl).hostname);

  const hostname = (() => { try { return new URL(finalUrl).hostname; } catch { return ""; } })();

  const [byTitle, byDomain] = await Promise.all([
    findRealSiteViaBrowser(query),
    hostname ? findRealSiteViaBrowser(hostname) : Promise.resolve([]),
  ]);

  const seen = new Set();
  const realSites = [...(byTitle ?? []), ...(byDomain ?? [])]
    .filter(s => {
      if (!s?.domain || seen.has(s.domain)) return false;
      s.domain = s.domain.replace(/^\[([^\]]+)\].*$/, "$1"); // clean markdown just in case
      seen.add(s.domain);
      return true;
    });

  console.log("combined realSites:", realSites);
  if (!realSites.length) return null;

  const actualDomain = finalHost;

  const domainMatch = realSites.find(
    s => s?.domain && (actualDomain === s.domain || actualDomain.endsWith(`.${s.domain}`))
  );
  if (domainMatch) return { phishing: false };

  const comparisons = await Promise.all(
    realSites.map(async site => {
      const realFaviconUrl = `https://${site.domain}/favicon.ico`;
      const comparison = await compareFavicons(favicon, realFaviconUrl);
      return { site, comparison };
    })
  );

  const bestMatch = comparisons
    .filter(c => c.comparison.likely_same)
    .sort((a, b) => a.comparison.distance - b.comparison.distance)[0];

  if (bestMatch) {
    return {
      phishing: true,
      confidence: "high",
      reason: "Favicon matches a known site but domain does not",
      spoofedBrand: bestMatch.site.domain,
      expectedUrl: bestMatch.site.url,
      faviconDistance: bestMatch.comparison.distance,
    };
  }

  const minDistance = Math.min(...comparisons.map(c => c.comparison.distance));
  return { phishing: false, faviconDistance: minDistance };
}