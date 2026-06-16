import { getDomainAge } from "./intel/rdap.js";
import { checkSafeBrowsing } from "./intel/safeBrowsing.js";

// Weighted scoring. Each rule contributes points + a human-readable reason.
// 0–24 safe, 25–59 suspicious, 60+ dangerous.
const THRESHOLDS = { suspicious: 25, dangerous: 60 };

/**
 * Turn a raw detonation report into a risk verdict.
 * Enriches with domain age (RDAP) + Safe Browsing (if key present).
 */
export async function scoreRisk(report) {
  const reasons = [];
  let score = 0;

  const add = (points, reason) => {
    score += points;
    reasons.push({ points, reason });
  };

  const s = report.signals || {};
  const host = s.finalHost || "";

  // --- Threat intelligence ---
  const [domainAge, safeBrowsing] = await Promise.all([
    getDomainAge(host),
    checkSafeBrowsing(report.finalUrl || report.requestedUrl),
  ]);

  if (safeBrowsing.listed) {
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

  // --- HTTP/transport ---
  try {
    const proto = new URL(report.finalUrl || report.requestedUrl).protocol;
    if (proto === "http:") add(10, "Final page served over insecure HTTP");
  } catch {
    /* ignore */
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
