const HIGH_VALUE_BRANDS = [
  "paypal", "apple", "icloud", "microsoft", "office365", "outlook",
  "google", "gmail", "amazon", "netflix", "facebook", "instagram",
  "whatsapp", "coinbase", "binance", "metamask", "chase", "wellsfargo",
  "usps", "dhl", "fedex", "irs",
];

const SCAM_TERMS = [
  "you won", "you have won", "winner", "claim your prize", "free gift card",
  "survey", "giveaway", "limited time offer", "act now", "cash prize",
  "congratulations", "claim now", "redeem now", "selected as winner",
];

const TECH_SUPPORT_TERMS = [
  "virus detected", "virus found", "your computer is infected", "computer infected",
  "security alert", "security warning", "critical alert", "trojan", "malware detected",
  "spyware", "ransomware", "windows defender", "microsoft support", "apple support",
  "call support", "call immediately", "do not close", "do not restart",
  "toll free", "support number", "error code", "system blocked",
];

const SUPPORT_PHONE_RE = /(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}/g;
const TRACKER_MARKERS = /analytics|tracking|pixel|doubleclick|googletagmanager|google-analytics|facebook|facebook.net|fbcdn|clarity|hotjar|segment|tiktok|criteo|scorecardresearch|quantserve|adnxs|taboola|bidr|gtm|matomo|sentry/i;

function normalizeHost(hostname) {
  return String(hostname || "")
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/:\d+$/, "")
    .split(".")
    .filter(Boolean);
}

function levenshteinDistance(a, b) {
  const left = a.toLowerCase();
  const right = b.toLowerCase();
  const matrix = Array.from({ length: left.length + 1 }, () => new Array(right.length + 1).fill(0));

  for (let i = 0; i <= left.length; i += 1) matrix[i][0] = i;
  for (let j = 0; j <= right.length; j += 1) matrix[0][j] = j;

  for (let i = 1; i <= left.length; i += 1) {
    for (let j = 1; j <= right.length; j += 1) {
      const cost = left[i - 1] === right[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }

  return matrix[left.length][right.length];
}

function normalizeHostname(value) {
  try {
    return new URL(value).hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return String(value || "").replace(/^www\./, "").toLowerCase();
  }
}

export function detectSurveyGiveawayScam(text) {
  const haystack = String(text || "").toLowerCase();
  const matchedTerms = SCAM_TERMS.filter((term) => haystack.includes(term));

  return {
    suspicious: matchedTerms.length > 0,
    matchedTerms,
  };
}

export function detectTechSupportScam(input = {}) {
  const runtime = input.runtime || {};
  const dialogText = Array.isArray(runtime.dialogSamples)
    ? runtime.dialogSamples.map((sample) => sample?.text || sample).join(" ")
    : "";
  const haystack = `${input.text || ""} ${dialogText}`.toLowerCase();
  const matchedTerms = TECH_SUPPORT_TERMS.filter((term) => haystack.includes(term));
  const phoneNumbers = [...new Set((haystack.match(SUPPORT_PHONE_RE) || []).map((value) => value.trim()))]
    .slice(0, 4);

  const fullscreenRequests = countValue(runtime.fullscreenRequests);
  const dialogCalls = countValue(runtime.dialogCalls);
  const exitLockHooks = countValue(runtime.exitLockHooks);

  const hasSupportContext = matchedTerms.length >= 2 || (matchedTerms.length >= 1 && phoneNumbers.length > 0);
  const hasLockBehavior = fullscreenRequests > 0 || dialogCalls > 0 || exitLockHooks > 0;

  return {
    suspicious: hasSupportContext && (hasLockBehavior || phoneNumbers.length > 0),
    matchedTerms,
    phoneNumbers,
    fullscreenRequests,
    dialogCalls,
    exitLockHooks,
  };
}

export function detectTyposquat(hostname) {
  const labels = normalizeHost(hostname);
  if (labels.length < 2) return null;

  const base = labels[0];
  const brandMatches = HIGH_VALUE_BRANDS
    .map((brand) => ({ brand, distance: levenshteinDistance(base, brand) }))
    .filter((item) => item.distance <= 2 && item.distance > 0)
    .sort((a, b) => a.distance - b.distance);

  return brandMatches.length > 0 ? { hostname, brand: brandMatches[0].brand, distance: brandMatches[0].distance } : null;
}

export function auditThirdPartyTrackers(externalUrls = [], finalUrl = "", cookies = [], storageKeys = []) {
  const baseHost = normalizeHostname(finalUrl);
  const thirdParty = (externalUrls || [])
    .map((value) => String(value || ""))
    .filter(Boolean)
    .filter((value) => {
      try {
        return normalizeHostname(value) !== baseHost;
      } catch {
        return false;
      }
    });

  const trackerDomains = [...new Set(thirdParty.filter((value) => TRACKER_MARKERS.test(value)))];

  return {
    thirdPartyCount: thirdParty.length,
    trackerCount: trackerDomains.length,
    trackerDomains,
    cookieCount: Array.isArray(cookies) ? cookies.length : 0,
    storageKeyCount: Array.isArray(storageKeys) ? storageKeys.length : 0,
  };
}

export function inspectTlsSecurity(url, securityDetails) {
  const details = securityDetails || {};
  const host = (() => {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return "";
    }
  })();

  const protocol = details.protocol || "unknown";
  const protocolNormalized = String(protocol || "").toLowerCase().replace(/\s+/g, "");
  const subjectName = details.subjectName || "";
  const issuer = details.issuer || "";
  const validFrom = details.validFrom || null;
  const validTo = details.validTo || null;
  const hostnameMismatch = Boolean(
    host &&
      subjectName &&
      !subjectName.toLowerCase().includes(host.replace(/^www\./, ""))
  );
  const expired = typeof validTo === "number" ? validTo * 1000 < Date.now() : false;
  const weakProtocol = /(?:^|[^0-9])(?:ssl|tlsv1\.[01])/.test(protocolNormalized);
  const selfSigned = /self[- ]?signed|localhost/i.test(issuer + " " + subjectName);

  return {
    protocol,
    subjectName,
    issuer,
    validFrom,
    validTo,
    hostnameMismatch,
    expired,
    weakProtocol,
    selfSigned,
    insecure: !/^https:/i.test(url),
    issues: [
      ...(hostnameMismatch ? ["Certificate subject does not match the destination host"] : []),
      ...(expired ? ["Certificate is expired or not yet valid"] : []),
      ...(weakProtocol ? ["TLS protocol is weaker than TLS 1.2/1.3"] : []),
      ...(selfSigned ? ["Certificate looks self-signed or unauthenticated"] : []),
      ...(!/^https:/i.test(url) ? ["Page is served over plain HTTP"] : []),
    ],
  };
}

function countValue(value) {
  if (typeof value === "number") return value;
  if (Array.isArray(value)) return value.length;
  return 0;
}

export function classifySignalThreats(signals = {}) {
  const reasons = [];
  let score = 0;

  const add = (points, reason) => {
    score += points;
    reasons.push({ points, reason });
  };

  const runtime = signals.runtime || {};
  const tls = signals.tls || {};
  const typosquat = signals.typosquat || null;
  const techSupportScam = signals.techSupportScam || detectTechSupportScam({
    text: `${signals.titleText || ""} ${signals.headingText || ""} ${signals.bodyText || ""}`,
    runtime,
  });
  const scam = detectSurveyGiveawayScam(`${signals.titleText || ""} ${signals.headingText || ""} ${signals.bodyText || ""}`);
  const trackerAudit = auditThirdPartyTrackers(
    signals.externalResourceUrls || [],
    signals.finalUrl || signals.requestedUrl || "",
    signals.cookieNames || [],
    signals.storageKeys || []
  );

  const clipboardWrites = countValue(runtime.clipboardWrites);
  const evalCalls = countValue(runtime.evalCalls);
  const functionCtorCalls = countValue(runtime.functionCtorCalls);
  const fullscreenRequests = countValue(runtime.fullscreenRequests);
  const keystrokeHooks = countValue(runtime.keystrokeHooks);
  const popunderAttempts = countValue(runtime.popunderAttempts);
  const sandboxProbes = countValue(runtime.sandboxProbes);
  const walletCalls = countValue(runtime.walletCalls);
  const walletProviders = countValue(runtime.walletProviders);
  const dialogCalls = countValue(runtime.dialogCalls);
  const exitLockHooks = countValue(runtime.exitLockHooks);

  if (scam.suspicious) add(18, `Survey/giveaway scam language detected: ${scam.matchedTerms.join(", ")}`);
  if (techSupportScam.suspicious) {
    add(35, `Tech-support scam indicators detected: ${techSupportScam.matchedTerms.slice(0, 4).join(", ")}`);
  }
  if (fullscreenRequests > 0) add(15, `Page requested fullscreen mode (${fullscreenRequests} request(s))`);
  if (dialogCalls > 0) add(12, `Blocking alert/confirm/prompt dialogs were triggered (${dialogCalls} call(s))`);
  if (exitLockHooks > 0) add(10, `Exit-lock style navigation hooks were attached (${exitLockHooks} hook(s))`);
  if (sandboxProbes > 0) add(20, `Page checked sandbox automation state via navigator.webdriver (${sandboxProbes} read(s))`);
  if (clipboardWrites > 0) add(8, `Clipboard write hooks were observed (${clipboardWrites} call(s))`);
  if ((evalCalls + functionCtorCalls) > 0) add(10, `Dynamic code execution hooks were observed (${evalCalls + functionCtorCalls} call(s))`);
  if (keystrokeHooks > 0) add(8, `Keylogging-style listener hooks were attached (${keystrokeHooks} listener(s))`);
  if (popunderAttempts > 0) add(12, `Window-opening/pop-under behavior was injected (${popunderAttempts} attempt(s))`);
  if (walletCalls > 0 || walletProviders > 0) add(25, "Wallet provider / connect behavior is present, a common drainers pattern");
  if (typosquat) add(18, `Typosquatted brand lookalike detected: ${typosquat.hostname} resembles ${typosquat.brand}`);

  if (trackerAudit.trackerCount > 0) add(8, `Third-party tracker domains were loaded (${trackerAudit.trackerCount})`);
  if (trackerAudit.thirdPartyCount >= 5) add(6, `Many third-party resources were loaded (${trackerAudit.thirdPartyCount})`);
  if (trackerAudit.cookieCount >= 5) add(5, `The page uses many cookies or cookie-like storage entries (${trackerAudit.cookieCount})`);
  if (trackerAudit.storageKeyCount >= 8) add(5, `Client-side storage is heavily used (${trackerAudit.storageKeyCount} keys)`);

  if (tls.insecure) add(10, "Page is served over plain HTTP");
  if (tls.hostnameMismatch) add(18, "TLS certificate subject does not match the destination host");
  if (tls.expired) add(20, "TLS certificate is expired or invalid");
  if (tls.weakProtocol) add(8, "TLS protocol is weaker than TLS 1.2/1.3");
  if (tls.selfSigned) add(12, "TLS certificate appears self-signed or unauthenticated");

  return { score, reasons };
}
