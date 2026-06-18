import { getDomainAge } from "./intel/rdap.js";
import { checkSafeBrowsing } from "./intel/safeBrowsing.js";
import { isTrustedDomain } from "./intel/trustedDomains.js";
import { isVerifiedHost } from "./intel/verifiedLinks.js";
import { classifySignalThreats } from "./threatSignals.js";

// Weighted scoring. Each rule contributes points + a human-readable reason.
// 0–24 safe, 25–59 suspicious, 60+ dangerous.
const THRESHOLDS = { suspicious: 25, dangerous: 60 };

/**
 * Turn a raw detonation report into a risk verdict.
 * Enriches with domain age (RDAP) + Safe Browsing unless the user disables
 * those optional layers.
 */
export async function scoreRisk(report, options = {}) {
  const reasons = [];
  let score = 0;
  const analysisLayers = options.analysisLayers || {};
  const includeDomainAge = analysisLayers.domainAge !== false;
  const includeSafeBrowsing = analysisLayers.safeBrowsing !== false;
  // Whether an auto-download blocks the trusted-domain clamp. Default true
  // (cautious); set false to trust downloads served from allowlisted/verified hosts.
  const downloadsAsHardDanger = analysisLayers.downloadsAsHardDanger !== false;

  const add = (points, reason) => {
    score += points;
    reasons.push({ points, reason });
  };

  const s = report.signals || {};
  const host = s.finalHost || "";
  const phishingSpoofedBrand = report.phishing && report.phishing.phishing === true;
  const runtimeThreatSummary = classifySignalThreats(s);

  score += runtimeThreatSummary.score;
  reasons.push(...runtimeThreatSummary.reasons);

  // --- Threat intelligence ---
  const [domainAge, safeBrowsing] = await Promise.all([
    includeDomainAge ? getDomainAge(host) : Promise.resolve({ skipped: true }),
    includeSafeBrowsing
      ? checkSafeBrowsing(report.finalUrl || report.requestedUrl)
      : Promise.resolve({ skipped: true }),
  ]);

  if (!safeBrowsing.skipped && safeBrowsing.listed) {
    add(60, `Google Safe Browsing flagged this URL: ${safeBrowsing.threats.join(", ")}`);
  }

  if (typeof domainAge.ageDays === "number") {
    if (domainAge.ageDays <= 7) {
      add(35, `Domain registered ${domainAge.ageDays} day(s) ago — brand-new`);
    } else if (domainAge.ageDays <= 30) {
      add(20, `Domain only ${domainAge.ageDays} days old`);
    } else if (domainAge.ageDays <= 90) {
      add(8, `Domain is fairly new (${domainAge.ageDays} days)`);
    }
  }

  // --- Brand impersonation ---
  if (s.brandImpersonation && s.brandImpersonation.length > 0) {
    add(
      30,
      `Page impersonates "${s.brandImpersonation.join('", "')}" but domain is ${host || "unknown"}`
    );
  }

  // --- Credential / payment harvesting ---
  if (s.crossDomainCredPost) {
    add(30, "Login form submits your password to a different domain");
  }
  if (s.passwordFields > 0) {
    add(15, `Page requests a password (${s.passwordFields} field(s))`);
  }
  if (s.paymentFields > 0) {
    add(20, `Page requests payment/card details (${s.paymentFields} field(s))`);
  }

  // --- Evasion / behavior ---
  if (report.redirectCount >= 3) {
    add(15, `Bounced through ${report.redirectCount} redirects before landing`);
  } else if (report.redirectCount === 2) {
    add(6, "Used 2 redirects");
  }
  if (report.downloads && report.downloads.length > 0) {
    add(35, `Tried to auto-download a file: ${report.downloads.map((d) => d.suggestedFilename || d.url).join(", ")}`);
  }
  if (report.blockedRequests && report.blockedRequests.length > 0) {
    add(40, `Tried to reach an internal/private address (blocked): ${report.blockedRequests.join(", ")}`);
  }
  if (s.metaRefresh) {
    add(5, "Uses a meta-refresh auto-redirect");
  }

  // --- Credential trap (dynamic proof) ---
  // The sandbox typed canary credentials and watched where the form tried to ship
  // them. A cross-domain destination is hard proof of credential theft — stronger
  // than the static crossDomainCredPost heuristic above.
  if (report.credentialTrap && report.credentialTrap.blocked) {
    if (report.credentialTrap.crossDomain) {
      add(
        35,
        `Sandbox proved the password is sent off-domain to ${report.credentialTrap.host} (blocked)`
      );
    } else {
      add(5, `Sandbox captured the credential submission to ${report.credentialTrap.host} (blocked)`);
    }
  }

  // --- HTTP/transport ---
  try {
    const proto = new URL(report.finalUrl || report.requestedUrl).protocol;
    if (proto === "http:") add(10, "Final page served over insecure HTTP");
  } catch {
    /* ignore */
  }

  // --- Common-sense / false-positive gate --------------------------------
  // A login page or redirect on a legitimate site (e.g. mail.google.com) is
  // expected behaviour, not phishing. Three legitimacy signals, weakest first.
  const flaggedBySafeBrowsing = !safeBrowsing.skipped && safeBrowsing.listed;

  // #3 — positive use of intel: a long-established, unflagged domain is less
  // likely hostile, so credit it. A credit (not a clamp) keeps real phishing on
  // aged/parked domains scoreable.
  const wellAged = typeof domainAge.ageDays === "number" && domainAge.ageDays >= 365;
  if (wellAged && !flaggedBySafeBrowsing) {
    add(-15, `Domain is well-established (${domainAge.ageDays} days) with no Safe Browsing hits`);
  }
  if (score < 0) score = 0;

  // Strong behavioral malice (tech-support scam, wallet drainer, sandbox
  // probing, fullscreen + blocking-dialog lockouts, etc.) is hard evidence of a
  // hostile page in its own right. Without this, scanning any page on a shared
  // host (e.g. all our demo decoys live on one *.vercel.app) marks the host
  // "verified", and the trust clamp below would wrongly downgrade a malicious
  // page to safe. The runtime threat score crossing this bar is malice we won't
  // discount on trust.
  const behavioralDanger = runtimeThreatSummary.score >= 35;

  // Hard evidence of compromise — never suppressed, even on a trusted domain
  // (covers hijacked legit sites / open redirects / subdomain takeover).
  const hardDanger =
    flaggedBySafeBrowsing ||
    behavioralDanger ||
    (report.blockedRequests && report.blockedRequests.length > 0) ||
    (downloadsAsHardDanger && report.downloads && report.downloads.length > 0) ||
    s.crossDomainCredPost ||
    (s.brandImpersonation && s.brandImpersonation.length > 0) ||
    phishingSpoofedBrand;

  // #1 allowlist + #2 user-verified: strong trust → clamp the verdict to safe
  // (unless hard danger above), discounting the benign login/redirect signals.
  const onAllowlist = isTrustedDomain(host);
  const userVerified = await isVerifiedHost(host);
  if (!hardDanger && (onAllowlist || userVerified)) {
    const why = onAllowlist
      ? `${host} is a recognized legitimate domain`
      : `${host} was previously verified by the user`;
    score = Math.min(score, THRESHOLDS.suspicious - 1);
    reasons.unshift({
      points: 0,
      reason: `Common-sense check: ${why}; benign login/redirect signals discounted`,
    });
  }

  if (phishingSpoofedBrand) {
    const spoofedBrand = report.phishing.spoofedBrand || "a known brand";
    add(35, `Brand impersonation detected: phishing detector matched ${spoofedBrand} while the domain does not match`);
  }

  const verdict =
    score >= THRESHOLDS.dangerous
      ? "dangerous"
      : score >= THRESHOLDS.suspicious
      ? "suspicious"
      : "safe";

  return {
    verdict,
    score,
    reasons: reasons.sort((a, b) => b.points - a.points),
    intel: {
      domainAge,
      safeBrowsing,
    },
  };
}
