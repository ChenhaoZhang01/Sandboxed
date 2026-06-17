const HIGH_VALUE_BRANDS = [
  "paypal", "apple", "icloud", "microsoft", "office365", "outlook",
  "google", "gmail", "amazon", "netflix", "facebook", "instagram",
  "whatsapp", "coinbase", "binance", "metamask", "chase", "wellsfargo",
  "usps", "dhl", "fedex", "irs",
];

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
  const weakProtocol = !/^tlsv1\.[23]$/i.test(protocol.replace(/\s+/g, ""));
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

  const clipboardWrites = countValue(runtime.clipboardWrites);
  const evalCalls = countValue(runtime.evalCalls);
  const functionCtorCalls = countValue(runtime.functionCtorCalls);
  const keystrokeHooks = countValue(runtime.keystrokeHooks);
  const popunderAttempts = countValue(runtime.popunderAttempts);
  const walletCalls = countValue(runtime.walletCalls);
  const walletProviders = countValue(runtime.walletProviders);

  if (clipboardWrites > 0) add(8, `Clipboard write hooks were observed (${clipboardWrites} call(s))`);
  if ((evalCalls + functionCtorCalls) > 0) add(10, `Dynamic code execution hooks were observed (${evalCalls + functionCtorCalls} call(s))`);
  if (keystrokeHooks > 0) add(8, `Keylogging-style listener hooks were attached (${keystrokeHooks} listener(s))`);
  if (popunderAttempts > 0) add(12, `Window-opening/pop-under behavior was injected (${popunderAttempts} attempt(s))`);
  if (walletCalls > 0 || walletProviders > 0) add(25, "Wallet provider / connect behavior is present, a common drainers pattern");
  if (typosquat) add(18, `Typosquatted brand lookalike detected: ${typosquat.hostname} resembles ${typosquat.brand}`);

  if (tls.insecure) add(10, "Page is served over plain HTTP");
  if (tls.hostnameMismatch) add(18, "TLS certificate subject does not match the destination host");
  if (tls.expired) add(20, "TLS certificate is expired or invalid");
  if (tls.weakProtocol) add(8, "TLS protocol is weaker than TLS 1.2/1.3");
  if (tls.selfSigned) add(12, "TLS certificate appears self-signed or unauthenticated");

  return { score, reasons };
}
