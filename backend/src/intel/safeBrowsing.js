// Google Safe Browsing v4 lookup — OPTIONAL.
// Free API key: https://developers.google.com/safe-browsing/v4/get-started
// If no key is configured, this no-ops and returns { skipped: true }.

const API_KEY = process.env.SAFE_BROWSING_API_KEY || "";

/**
 * Check a URL against Google's threat lists.
 * Returns { listed: boolean, threats: string[] } or { skipped } / { error }.
 */
export async function checkSafeBrowsing(url) {
  if (!API_KEY) return { skipped: true };

  const body = {
    client: { clientId: "sandboxed", clientVersion: "0.1.0" },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  };

  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 6000);
    const res = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      }
    );
    clearTimeout(t);

    if (!res.ok) return { error: `safebrowsing-${res.status}` };
    const data = await res.json();
    const matches = data.matches || [];
    return {
      listed: matches.length > 0,
      threats: matches.map((m) => m.threatType),
    };
  } catch (err) {
    return { error: err.name === "AbortError" ? "timeout" : "fetch-failed" };
  }
}
