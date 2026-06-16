import puppeteer from "puppeteer";
import { isBlockedUrl, isBlockedLiteral } from "./ssrf.js";

const DETONATE_TIMEOUT_MS = Number(process.env.DETONATE_TIMEOUT_MS || 15000);
const MAX_REDIRECTS = Number(process.env.MAX_REDIRECTS || 15);

// A realistic UA so phishing kits behave normally (many cloak against headless).
const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

// Brand keywords commonly impersonated. If the page screams "PayPal" but the
// domain isn't paypal.com, that's a strong phishing signal.
const BRAND_KEYWORDS = [
  "paypal", "apple", "icloud", "microsoft", "office365", "outlook",
  "google", "gmail", "amazon", "netflix", "facebook", "instagram",
  "whatsapp", "coinbase", "binance", "metamask", "wallet", "bank",
  "chase", "wells fargo", "usps", "dhl", "fedex", "irs", "gov",
];

let browserPromise = null;

/**
 * Reuse a single browser instance across detonations for speed.
 * Each detonation still gets its own isolated incognito context + page.
 */
async function getBrowser() {
  if (!browserPromise) {
    browserPromise = puppeteer.launch({
      headless: true,
      args: [
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
      ],
    });
  }
  return browserPromise;
}

export async function closeBrowser() {
  if (browserPromise) {
    const b = await browserPromise;
    await b.close();
    browserPromise = null;
  }
}

/**
 * Detonate a URL: open it in an isolated browser context, follow the full
 * redirect chain, screenshot the landing page, and extract behavioral signals.
 *
 * @param {string} targetUrl
 * @returns {Promise<object>} raw detonation report (no verdict — that's risk.js)
 */
export async function detonate(targetUrl) {
  const browser = await getBrowser();
  // Incognito context = clean cookies/storage per detonation (sandbox-ish).
  const context = await browser.createBrowserContext();
  const page = await context.newPage();

  const redirectChain = [];
  const downloads = [];
  const blocked = [];
  let mainStatus = null;

  try {
    await page.setUserAgent(USER_AGENT);
    await page.setViewport({ width: 1280, height: 800 });

    // Block actual file downloads from hitting disk; just record intent.
    const client = await page.target().createCDPSession();
    await client.send("Page.setDownloadBehavior", { behavior: "deny" }).catch(() => {});
    client.on("Page.downloadWillBegin", (e) => {
      downloads.push({ url: e.url, suggestedFilename: e.suggestedFilename || null });
    });

    // Request interception lets us (a) record the redirect chain, (b) enforce
    // SSRF on every navigation hop, and (c) actually abort runaway redirects.
    await page.setRequestInterception(true);
    page.on("request", async (req) => {
      try {
        const url = req.url();
        const isNav =
          req.isNavigationRequest() && req.frame() === page.mainFrame();

        if (isNav && url !== "about:blank") {
          redirectChain.push(url);
          if (redirectChain.length > MAX_REDIRECTS) {
            return await req.abort("failed");
          }
        }

        if (/^https?:/i.test(url)) {
          // Cheap literal-IP block on ALL resources (subresources included).
          if (isBlockedLiteral(url)) {
            blocked.push(url);
            return await req.abort("blockedbyclient");
          }
          // Strict DNS-resolving block on navigations (catches redirect-to-
          // metadata and DNS-based SSRF that the literal check can't see).
          if (isNav && (await isBlockedUrl(url))) {
            blocked.push(url);
            return await req.abort("blockedbyclient");
          }
        }

        return await req.continue();
      } catch {
        // Request may already be handled/aborted; ignore.
        try {
          await req.abort("failed");
        } catch {
          /* noop */
        }
      }
    });

    let response = null;
    try {
      response = await page.goto(targetUrl, {
        waitUntil: "networkidle2",
        timeout: DETONATE_TIMEOUT_MS,
      });
    } catch (navErr) {
      // Timeouts are common on heavy/hostile pages — keep whatever loaded.
      response = page.mainFrame().url() ? null : null;
    }
    mainStatus = response ? response.status() : null;

    const finalUrl = page.url();
    let title = "";
    try {
      title = await page.title();
    } catch {
      title = "";
    }

    const signals = await extractSignals(page, finalUrl);

    let screenshot = null;
    try {
      screenshot = await page.screenshot({ type: "jpeg", quality: 60, encoding: "base64" });
    } catch {
      screenshot = null;
    }

    return {
      requestedUrl: targetUrl,
      finalUrl,
      finalStatus: mainStatus,
      title,
      redirectChain: dedupeChain(redirectChain, finalUrl),
      redirectCount: Math.max(0, dedupeChain(redirectChain, finalUrl).length - 1),
      downloads,
      blockedRequests: blocked,
      signals,
      screenshotBase64: screenshot,
      detonatedAt: new Date().toISOString(),
    };
  } finally {
    await context.close().catch(() => {});
  }
}

function dedupeChain(chain, finalUrl) {
  const out = [];
  for (const u of chain) {
    if (u === "about:blank") continue;
    if (out[out.length - 1] !== u) out.push(u);
  }
  if (finalUrl && finalUrl !== "about:blank" && out[out.length - 1] !== finalUrl) {
    out.push(finalUrl);
  }
  return out;
}

/**
 * Run inside the page to collect phishing-relevant DOM signals.
 */
async function extractSignals(page, finalUrl) {
  let finalHost = "";
  try {
    finalHost = new URL(finalUrl).hostname.replace(/^www\./, "");
  } catch {
    finalHost = "";
  }

  const dom = await page.evaluate(() => {
    const lower = (s) => (s || "").toLowerCase();

    const passwordFields = document.querySelectorAll('input[type="password"]').length;

    const ccInputs = Array.from(document.querySelectorAll("input")).filter((el) => {
      const hay = lower(
        [el.name, el.id, el.placeholder, el.getAttribute("autocomplete")].join(" ")
      );
      return /card|cc-number|creditcard|cvv|cvc|card-number|expiry/.test(hay);
    }).length;

    const forms = Array.from(document.querySelectorAll("form")).map((f) => ({
      action: f.action || "",
      method: (f.method || "get").toLowerCase(),
      hasPassword: !!f.querySelector('input[type="password"]'),
    }));

    const metaRefresh = !!document.querySelector('meta[http-equiv="refresh" i]');

    const externalScripts = Array.from(document.querySelectorAll("script[src]"))
      .map((s) => s.src)
      .filter(Boolean);

    const bodyText = lower(document.body ? document.body.innerText : "").slice(0, 5000);
    const titleText = lower(document.title);
    const headingText = lower(
      Array.from(document.querySelectorAll("h1, h2"))
        .map((h) => h.innerText)
        .join(" ")
    ).slice(0, 1000);

    return {
      passwordFields,
      ccInputs,
      forms,
      metaRefresh,
      externalScriptCount: externalScripts.length,
      bodyText,
      titleText,
      headingText,
    };
  });

  // Brand-impersonation: page claims to be a brand but lives on an unrelated
  // domain. To avoid false positives we (a) ignore federated-login mentions like
  // "Sign in with Apple", which appear on many legitimate pages, and (b) require
  // the brand to appear in PROMINENT text (title/headings) — where real phishing
  // puts it — rather than anywhere in the body.
  const ssoPhrase =
    /\b(?:sign[\s-]?in|sign[\s-]?up|log[\s-]?in|login|continue|register|connect)\s+with\s+\w+/g;
  const prominent = `${dom.titleText} ${dom.headingText}`.replace(ssoPhrase, " ");
  const brandMentions = [];
  for (const brand of [
    "paypal", "apple", "icloud", "microsoft", "office365", "outlook",
    "google", "gmail", "amazon", "netflix", "facebook", "instagram",
    "whatsapp", "coinbase", "binance", "metamask", "chase", "wells fargo",
    "usps", "dhl", "fedex", "irs",
  ]) {
    const re = new RegExp(`\\b${brand.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`);
    if (re.test(prominent)) {
      const brandRoot = brand.replace(/\s+/g, "");
      if (finalHost && !finalHost.includes(brandRoot)) brandMentions.push(brand);
    }
  }

  // Forms that POST credentials to a different host than the page.
  const crossDomainCredPost = dom.forms.some((f) => {
    if (!f.hasPassword || !f.action) return false;
    try {
      const actionHost = new URL(f.action, finalUrl).hostname.replace(/^www\./, "");
      return actionHost && finalHost && actionHost !== finalHost;
    } catch {
      return false;
    }
  });

  return {
    finalHost,
    passwordFields: dom.passwordFields,
    paymentFields: dom.ccInputs,
    formCount: dom.forms.length,
    crossDomainCredPost,
    metaRefresh: dom.metaRefresh,
    externalScriptCount: dom.externalScriptCount,
    brandImpersonation: brandMentions,
  };
}
