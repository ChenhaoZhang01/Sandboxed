// phishing-detect.js
import { compareFavicons } from "./favicon-compare.js";
import { findRealSiteViaBrowser } from "./brand-search.js";
import { runWithTimeout } from "../src/timeouts.js";

const BRAND_SEARCH_TIMEOUT_MS = Number(process.env.BRAND_SEARCH_TIMEOUT_MS || 3000);
const MAX_SEARCH_RESULTS = Number(process.env.MAX_SEARCH_RESULTS || 3);
const MAX_FAVICON_COMPARISONS = Number(process.env.MAX_FAVICON_COMPARISONS || 3);

export async function checkForPhishing(report) {
    const { finalUrl, title, h1s, favicon, signals } = report;
    const finalHost = signals?.finalHost ?? new URL(finalUrl).hostname.replace(/^www\./, "");
  const query = title || h1s[0];
  if (!query) return null;

  console.log("searching for:", query, "and hostname:", new URL(finalUrl).hostname);

  const hostname = (() => { try { return new URL(finalUrl).hostname; } catch { return ""; } })();

  const searchQueries = [query].filter(Boolean);
  if (hostname && !searchQueries.includes(hostname)) {
    searchQueries.push(hostname);
  }

  const results = await Promise.allSettled(
    searchQueries.map((term) =>
      runWithTimeout(findRealSiteViaBrowser(term), BRAND_SEARCH_TIMEOUT_MS, [])
    )
  );

  const seen = new Set();
  const realSites = results
    .flatMap((r) => (r.status === "fulfilled" ? r.value : []))
    .filter((s) => {
      if (!s?.domain || seen.has(s.domain)) return false;
      s.domain = s.domain.replace(/^\[([^\]]+)\].*$/, "$1"); // clean markdown just in case
      seen.add(s.domain);
      return true;
    })
    .slice(0, MAX_SEARCH_RESULTS);

  console.log("combined realSites:", realSites);
  if (!realSites.length) return null;

  const actualDomain = finalHost;

  const domainMatch = realSites.find(
    s => s?.domain && (actualDomain === s.domain || actualDomain.endsWith(`.${s.domain}`))
  );
  if (domainMatch) return { phishing: false };

  const candidates = realSites.slice(0, MAX_FAVICON_COMPARISONS);
  const comparisons = await Promise.allSettled(
    candidates.map(async (site) => {
      const realFaviconUrl = `https://${site.domain}/favicon.ico`;
      const comparison = await compareFavicons(favicon, realFaviconUrl);
      return { site, comparison };
    })
  );

  const comparisonResults = comparisons
    .filter((item) => item.status === "fulfilled")
    .map((item) => item.value);

  const bestMatch = comparisonResults
    .filter((c) => c.comparison.likely_same)
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

  const minDistance = comparisonResults.length
    ? Math.min(...comparisonResults.map((c) => c.comparison.distance))
    : Infinity;
  return { phishing: false, faviconDistance: minDistance };
}