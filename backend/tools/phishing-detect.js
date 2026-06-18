// phishing-detect.js
import { compareFavicons } from "./favicon-compare.js";
import { findRealSiteViaBrowser } from "./brand-search.js";
import { runWithTimeout } from "../src/timeouts.js";

const BRAND_SEARCH_TIMEOUT_MS = Number(process.env.BRAND_SEARCH_TIMEOUT_MS || 3000);
const MAX_SEARCH_RESULTS = Number(process.env.MAX_SEARCH_RESULTS || 3);
const MAX_FAVICON_COMPARISONS = Number(process.env.MAX_FAVICON_COMPARISONS || 3);

export function normalizeDomain(hostname) {
  return String(hostname || "")
    .trim()
    .toLowerCase()
    .replace(/^www\./, "");
}

export function extractSearchQuery(rawText) {
  const cleaned = String(rawText || "")
    .replace(/\s*[-–—|•<>]+\s*/g, " | ")
    .replace(/\s+/g, " ")
    .trim();

  const parts = cleaned
    .split("|")
    .map((part) => part.replace(/\b(?:official|home|login|sign\s*in|sign\s*up|support|help|website)\b/gi, " ").trim())
    .filter(Boolean);

  return parts[parts.length - 1] || cleaned;
}

export function shouldSkipBrandSearch(query, hostname) {
  const queryRoot = normalizeDomain(extractSearchQuery(query)).replace(/\.[^.]+$/, "");
  const hostRoot = normalizeDomain(hostname).replace(/\.[^.]+$/, "");

  return Boolean(
    queryRoot &&
      hostRoot &&
      (queryRoot === hostRoot || hostRoot.includes(queryRoot) || queryRoot.includes(hostRoot))
  );
}

export async function checkForPhishing(report) {
    const { finalUrl, title, h1s, favicon, signals } = report;
    const finalHost = normalizeDomain(signals?.finalHost ?? new URL(finalUrl).hostname);
  const query = extractSearchQuery(title || h1s[0]);
  if (!query) return null;

  console.log("searching for:", query, "and hostname:", new URL(finalUrl).hostname);

  const hostname = (() => { try { return normalizeDomain(new URL(finalUrl).hostname); } catch { return ""; } })();

  if (shouldSkipBrandSearch(query, hostname)) {
    return null;
  }

  const querySet = new Set(
    [query, hostname]
      .filter(Boolean)
      .map((term) => normalizeDomain(term))
      .map((term) => term.replace(/\.(com|net|org|io|co|dev)$/i, ""))
      .map((term) => term.replace(/^www\./i, ""))
      .map((term) => term.trim())
      .filter(Boolean)
      .filter((term, index, list) => list.indexOf(term) === index)
  );

  const searchQueries = [...querySet].filter((term) => {
    const hostRoot = normalizeDomain(hostname).replace(/\.(com|net|org|io|co|dev)$/i, "");
    return term === hostRoot || term.includes(hostRoot) || !hostRoot || !hostname || term !== normalizeDomain(hostname);
  });

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
      s.domain = normalizeDomain(s.domain.replace(/^\[([^\]]+)\].*$/, "$1"));
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
  if (domainMatch) return { phishing: false, reason: "Domain already matches the real site" };

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