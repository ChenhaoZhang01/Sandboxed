import puppeteer from "puppeteer";
import { isBlockedUrl, isBlockedLiteral } from "./ssrf.js";
import { detectTechSupportScam, detectTyposquat, inspectTlsSecurity } from "./threatSignals.js";
import { makeCanary, fillCredentialForm, matchCanaryHit } from "./credentialTrap.js";

const DETONATE_TIMEOUT_MS = Number(process.env.DETONATE_TIMEOUT_MS || 30000);
const MAX_REDIRECTS = Number(process.env.MAX_REDIRECTS || 15);
const SCREENSHOT_DELAY_MS = Number(process.env.SCREENSHOT_DELAY_MS || 1500);
// Recorded-replay screencast tuning + how long to wait for the canary submission.
const REPLAY_MAX_FRAMES = Number(process.env.REPLAY_MAX_FRAMES || 30);
const CREDENTIAL_TRAP_WAIT_MS = Number(process.env.CREDENTIAL_TRAP_WAIT_MS || 3000);

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
export async function getBrowser() {
  if (!browserPromise) {
    const args = [
      "--no-sandbox",
      "--disable-setuid-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
    ];
    // Some restricted container runtimes (e.g. Railway) block the syscalls
    // Chrome's zygote uses to drop capabilities, so it crashes at
    // sandbox/credentials.cc even with --no-sandbox. On those hosts set
    // CHROME_SINGLE_PROCESS=1 to disable the zygote + run single-process. Leave
    // it UNSET where the sandbox works (Fly.io, Cloud Run, local) — single-process
    // Chrome is less stable on heavy pages, so we only opt in where required.
    if (process.env.CHROME_SINGLE_PROCESS === "1") {
      args.push("--no-zygote", "--single-process");
    }
    browserPromise = puppeteer.launch({ headless: true, args });
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

async function installThreatHooks(page) {
  const inject =
    typeof page.addInitScript === "function"
      ? page.addInitScript.bind(page)
      : typeof page.evaluateOnNewDocument === "function"
        ? page.evaluateOnNewDocument.bind(page)
        : null;

  if (!inject) {
    throw new Error("This Puppeteer runtime does not support page init hooks");
  }

  await inject(() => {
    const tracker = window.__sandboxedThreatSignals || (window.__sandboxedThreatSignals = {
      clipboardWrites: 0,
      clipboardSamples: [],
      dialogCalls: 0,
      dialogSamples: [],
      evalCalls: 0,
      exitLockHooks: 0,
      functionCtorCalls: 0,
      fullscreenRequests: 0,
      keystrokeHooks: 0,
      popunderAttempts: 0,
      sandboxProbes: 0,
      sandboxProbeProperties: [],
      walletCalls: 0,
      walletProviders: [],
    });

    const bump = (key, value = 1) => {
      tracker[key] = (tracker[key] || 0) + value;
    };

    const markWalletProvider = (name) => {
      if (!tracker.walletProviders.includes(name)) tracker.walletProviders.push(name);
    };

    const markSandboxProbe = (name) => {
      if (!tracker.sandboxProbeProperties.includes(name)) {
        tracker.sandboxProbeProperties.push(name);
      }
    };

    const recordClipboardText = (value) => {
      const text = String(value || "");
      tracker.clipboardWrites = (tracker.clipboardWrites || 0) + 1;
      if (text) tracker.clipboardSamples.push(text.slice(0, 160));
      if (tracker.clipboardSamples.length > 8) tracker.clipboardSamples.shift();
    };

    const recordDialog = (type, value) => {
      const text = String(value || "");
      tracker.dialogCalls = (tracker.dialogCalls || 0) + 1;
      tracker.dialogSamples.push({ type, text: text.slice(0, 220) });
      if (tracker.dialogSamples.length > 8) tracker.dialogSamples.shift();
    };

    const wrapWalletProvider = (name, provider) => {
      if (!provider || typeof provider !== "object") return provider;
      const request = provider.request?.bind(provider);
      if (typeof request === "function") {
        provider.request = async (...args) => {
          bump("walletCalls");
          markWalletProvider(name);
          return request(...args);
        };
      }
      return provider;
    };

    try {
      const originalOpen = window.open.bind(window);
      window.open = (...args) => {
        bump("popunderAttempts");
        return originalOpen(...args);
      };
    } catch {}

    try {
      const originalAlert = window.alert.bind(window);
      window.alert = (message) => {
        recordDialog("alert", message);
        return undefined;
      };
      window.alert.__sandboxedOriginal = originalAlert;
    } catch {}

    try {
      const originalConfirm = window.confirm.bind(window);
      window.confirm = (message) => {
        recordDialog("confirm", message);
        return false;
      };
      window.confirm.__sandboxedOriginal = originalConfirm;
    } catch {}

    try {
      const originalPrompt = window.prompt.bind(window);
      window.prompt = (message) => {
        recordDialog("prompt", message);
        return null;
      };
      window.prompt.__sandboxedOriginal = originalPrompt;
    } catch {}

    try {
      const originalEval = window.eval.bind(window);
      window.eval = (...args) => {
        bump("evalCalls");
        return originalEval(...args);
      };
    } catch {}

    try {
      const OriginalFunction = window.Function;
      window.Function = function (...args) {
        bump("functionCtorCalls");
        return new OriginalFunction(...args);
      };
      window.Function.prototype = OriginalFunction.prototype;
    } catch {}

    try {
      const originalAddEventListener = EventTarget.prototype.addEventListener;
      EventTarget.prototype.addEventListener = function (type, listener, options) {
        const eventType = String(type);
        if (/key|keyup|keydown|keypress|input|paste|clipboard/i.test(eventType)) {
          bump("keystrokeHooks");
        }
        if (/beforeunload|unload|popstate|hashchange/i.test(eventType)) {
          bump("exitLockHooks");
        }
        return originalAddEventListener.call(this, type, listener, options);
      };
    } catch {}

    try {
      const wrapFullscreen = (proto) => {
        if (!proto || typeof proto.requestFullscreen !== "function") return;
        const originalRequestFullscreen = proto.requestFullscreen;
        proto.requestFullscreen = function (...args) {
          bump("fullscreenRequests");
          return originalRequestFullscreen.apply(this, args);
        };
      };
      wrapFullscreen(Element.prototype);
    } catch {}

    try {
      const desc = Object.getOwnPropertyDescriptor(Navigator.prototype, "webdriver");
      if (desc && desc.configurable !== false) {
        Object.defineProperty(Navigator.prototype, "webdriver", {
          configurable: true,
          enumerable: desc.enumerable,
          get() {
            bump("sandboxProbes");
            markSandboxProbe("navigator.webdriver");
            return desc.get ? desc.get.call(this) : desc.value;
          },
        });
      }
    } catch {}

    try {
      if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        const originalWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);
        navigator.clipboard.writeText = async (text) => {
          recordClipboardText(text);
          return originalWriteText(text);
        };
      }
    } catch {}

    try {
      const hookProvider = (name) => {
        const desc = Object.getOwnPropertyDescriptor(window, name);
        if (!desc || desc.configurable === false) return;

        Object.defineProperty(window, name, {
          configurable: true,
          enumerable: true,
          get() {
            const provider = desc.get ? desc.get.call(window) : desc.value;
            return wrapWalletProvider(name, provider);
          },
          set(v) {
            if (typeof v === "object" && v) {
              wrapWalletProvider(name, v);
            }
            if (desc.set) {
              desc.set.call(window, v);
            } else if (desc.writable) {
              desc.value = v;
            }
          },
        });
      };

      hookProvider("ethereum");
      hookProvider("solana");
    } catch {}
  });
}

/**
 * Detonate a URL: open it in an isolated browser context, follow the full
 * redirect chain, screenshot the landing page, and extract behavioral signals.
 *
 * @param {string} targetUrl
 * @returns {Promise<object>} raw detonation report (no verdict — that's risk.js)
 */
export async function detonate(targetUrl, options = {}) {
  const recordReplay = options.recordReplay !== false; // default on
  const credentialTrapEnabled = options.credentialTrap === true; // opt-in
  const startedAt = Date.now();
  const onProgress = typeof options.onProgress === "function" ? options.onProgress : () => {};
  const emitProgress = (stage, message, extra = {}) => {
    try {
      onProgress({ stage, message, elapsedMs: Date.now() - startedAt, ...extra });
    } catch {
      /* progress observers are best-effort */
    }
  };

  emitProgress("launching", "launching sandbox");
  const browser = await getBrowser();
  // Incognito context = clean cookies/storage per detonation (sandbox-ish).
  const context = await browser.createBrowserContext();
  const page = await context.newPage();

  const redirectChain = [];
  const downloads = [];
  const blocked = [];
  let mainStatus = null;

  // Credential-trap state. Armed AFTER the main report is captured so the trap
  // never perturbs scoring; the request handler below watches for the canary.
  const canary = makeCanary();
  let trapArmed = false;
  let trapFinalHost = "";
  let credentialTrapResult = null;

  // Recorded-replay frames captured via CDP screencast (when enabled).
  const replayFrames = [];
  const replayStarted = Date.now();

  try {
    emitProgress("instrumenting", "installing safety hooks");
    await installThreatHooks(page);

    await page.setUserAgent(USER_AGENT);
    await page.setViewport({ width: 1280, height: 800 });

    // Block actual file downloads from hitting disk; just record intent.
    const client = await page.target().createCDPSession();
    await client.send("Page.setDownloadBehavior", { behavior: "deny" }).catch(() => {});
    client.on("Page.downloadWillBegin", (e) => {
      downloads.push({ url: e.url, suggestedFilename: e.suggestedFilename || null });
    });

    // Recorded replay: stream the page as low-res JPEG frames so the user can
    // scrub through what happened. Capped at REPLAY_MAX_FRAMES; we ack each frame
    // (required by CDP) and stop the screencast before the final screenshot.
    if (recordReplay) {
      client.on("Page.screencastFrame", (frame) => {
        if (replayFrames.length < REPLAY_MAX_FRAMES) {
          replayFrames.push({ data: frame.data, offsetMs: Date.now() - replayStarted });
        }
        client
          .send("Page.screencastFrameAck", { sessionId: frame.sessionId })
          .catch(() => {});
      });
      await client.send("Page.enable").catch(() => {});
      await client
        .send("Page.startScreencast", {
          format: "jpeg",
          quality: 50,
          maxWidth: 800,
          maxHeight: 500,
          everyNthFrame: 1,
        })
        .catch(() => {});
    }

    // Request interception lets us (a) record the redirect chain, (b) enforce
    // SSRF on every navigation hop, and (c) actually abort runaway redirects.
    await page.setRequestInterception(true);
    page.on("request", async (req) => {
      try {
        const url = req.url();

        // Credential trap: if the canary submission is going out, capture WHERE it
        // would land and abort it so the (fake) password never actually leaves.
        if (trapArmed && !credentialTrapResult) {
          const hit = matchCanaryHit(req, canary.token, trapFinalHost);
          if (hit) {
            credentialTrapResult = hit;
            return await req.abort("blockedbyclient");
          }
        }

        const isNav =
          req.isNavigationRequest() && req.frame() === page.mainFrame();

        if (isNav && url !== "about:blank") {
          redirectChain.push(url);
          emitProgress("redirect", `redirect ${redirectChain.length}/${MAX_REDIRECTS}`, {
            index: redirectChain.length,
            max: MAX_REDIRECTS,
            url,
          });
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
      emitProgress("navigating", "opening target");
      response = await page.goto(targetUrl, {
        waitUntil: "domcontentloaded",
        timeout: DETONATE_TIMEOUT_MS,
      });
    } catch (navErr) {
      // Timeouts are common on heavy/hostile pages — keep whatever loaded.
      response = page.mainFrame().url() ? null : null;
    }
    mainStatus = response ? response.status() : null;

    const finalUrl = page.url();

    emitProgress("extracting", "extracting page signals");
    const pageMeta = await extractPageData(page);
    const runtimeSignals = await collectRuntimeSignals(page);
    const tlsSignals = await inspectTls(page, finalUrl);
    const signalData = await extractSignals(page, finalUrl, runtimeSignals);
    const cookieNames = (await page.cookies().catch(() => [])).map((cookie) => cookie.name);
    const signals = {
      ...signalData,
      cookieNames,
      runtime: runtimeSignals,
      tls: tlsSignals,
      typosquat: detectTyposquat(new URL(finalUrl).hostname || ""),
    };

    // Give heavy / animated pages a brief moment to settle before capturing
    // the final screenshot (helps with loading-overlay pages like x.com).
    emitProgress("screenshotting", "screenshotting");
    if (SCREENSHOT_DELAY_MS > 0) {
      await new Promise((resolve) => setTimeout(resolve, SCREENSHOT_DELAY_MS));
    }

    let screenshot = null;
    try {
      screenshot = await page.screenshot({ type: "jpeg", quality: 60, encoding: "base64" });
    } catch {
      screenshot = null;
    }

    if (recordReplay) {
      await client.send("Page.stopScreencast").catch(() => {});
    }

    // Credential trap runs LAST so it can't perturb the report above. Only bother
    // if there's a password field to fill. We fill canary creds, submit, and wait
    // briefly for the request handler to catch (and abort) the outbound submission.
    let credentialTrap = null;
    if (credentialTrapEnabled && signals.passwordFields > 0) {
      emitProgress("credential-trap", "checking credential trap");
      trapFinalHost = signals.finalHost || "";
      trapArmed = true;
      const attempted = await fillCredentialForm(page, canary);
      if (attempted) {
        const deadline = Date.now() + CREDENTIAL_TRAP_WAIT_MS;
        while (!credentialTrapResult && Date.now() < deadline) {
          await new Promise((r) => setTimeout(r, 100));
        }
      }
      trapArmed = false;
      credentialTrap = credentialTrapResult
        ? {
            attempted: true,
            blocked: true,
            target: credentialTrapResult.url,
            host: credentialTrapResult.host,
            method: credentialTrapResult.method,
            crossDomain: credentialTrapResult.crossDomain,
          }
        : { attempted, blocked: false, target: null, host: null, crossDomain: false };
    }

    return {
      requestedUrl: targetUrl,
      finalUrl,
      finalStatus: mainStatus,
      title: pageMeta.title,
      favicon: pageMeta.favicon,
      h1s: pageMeta.h1s,
      redirectChain: dedupeChain(redirectChain, finalUrl),
      redirectCount: Math.max(0, dedupeChain(redirectChain, finalUrl).length - 1),
      downloads,
      blockedRequests: blocked,
      signals,
      screenshotBase64: screenshot,
      replayFrames,
      credentialTrap,
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
async function extractSignals(page, finalUrl, runtimeSignals = {}) {
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

    const externalResourceUrls = Array.from(
      document.querySelectorAll("script[src], iframe[src], img[src], link[href], video[src], audio[src], source[src], a[href]")
    )
      .map((el) => (el.getAttribute("src") || el.getAttribute("href") || "").trim())
      .filter(Boolean)
      .filter((value) => /^https?:/i.test(value))
      .filter((value, index, list) => list.indexOf(value) === index);

    const storageKeys = Array.from(
      new Set([
        ...Object.keys(window.localStorage || {}),
        ...Object.keys(window.sessionStorage || {}),
      ])
    );

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
      externalScriptCount: externalResourceUrls.length,
      externalResourceUrls,
      storageKeys,
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
    techSupportScam: detectTechSupportScam({
      text: `${dom.titleText} ${dom.headingText} ${dom.bodyText}`,
      runtime: runtimeSignals,
    }),
  };
}


async function collectRuntimeSignals(page) {
  try {
    return await page.evaluate(() => ({
      ...(window.__sandboxedThreatSignals || {}),
      sandboxProbeProperties: Array.isArray(window.__sandboxedThreatSignals?.sandboxProbeProperties)
        ? [...window.__sandboxedThreatSignals.sandboxProbeProperties]
        : [],
      walletProviders: Array.isArray(window.__sandboxedThreatSignals?.walletProviders)
        ? [...window.__sandboxedThreatSignals.walletProviders]
        : [],
      clipboardSamples: Array.isArray(window.__sandboxedThreatSignals?.clipboardSamples)
        ? [...window.__sandboxedThreatSignals.clipboardSamples]
        : [],
      dialogSamples: Array.isArray(window.__sandboxedThreatSignals?.dialogSamples)
        ? [...window.__sandboxedThreatSignals.dialogSamples]
        : [],
    }));
  } catch {
    return {};
  }
}

async function inspectTls(page, finalUrl) {
  const cdp = await page.target().createCDPSession().catch(() => null);
  if (!cdp) return inspectTlsSecurity(finalUrl, {});

  try {
    const [securityState, cert] = await Promise.all([
      cdp.send("Security.getSecurityState", { origin: finalUrl }).catch(() => ({})),
      cdp.send("Security.getCertificate", { origin: finalUrl }).catch(() => ({})),
    ]);

    return inspectTlsSecurity(finalUrl, {
      protocol: securityState.protocol || securityState.securityState || "unknown",
      subjectName: cert.subjectName || cert.certificate?.subjectName || "",
      issuer: cert.issuer || cert.certificate?.issuer || "",
      validFrom: cert.validFrom || cert.certificate?.validFrom || null,
      validTo: cert.validTo || cert.certificate?.validTo || null,
    });
  } catch {
    return inspectTlsSecurity(finalUrl, {});
  }
}

async function extractPageData(page){
  const pageMeta = await page.evaluate(() => {
    // Favicon: prefer <link rel="icon"> variants, fall back to /favicon.ico
    const faviconEl =
      document.querySelector('link[rel="icon"]') ||
      document.querySelector('link[rel="shortcut icon"]') ||
      document.querySelector('link[rel="apple-touch-icon"]');
    const favicon = faviconEl
      ? new URL(faviconEl.href, location.href).href
      : new URL("/favicon.ico", location.href).href;

    // Title
    const title = document.title || null;

    // H1s (trim whitespace, filter empties, cap at 10)
    const h1s = [...document.querySelectorAll("h1")]
      .map((el) => el.innerText.trim())
      .filter(Boolean)
      .slice(0, 10);

    return { favicon, title, h1s };
  });
  return pageMeta;
}
