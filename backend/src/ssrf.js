// SSRF guard. Detonation fetches attacker-controlled URLs, so this is the
// most security-critical module: it must stop the engine from being abused to
// reach internal services, cloud metadata (169.254.169.254), or loopback.
import dns from "node:dns";
import ipaddr from "ipaddr.js";
import { runWithTimeout } from "./timeouts.js";

const DNS_LOOKUP_TIMEOUT_MS = Number(process.env.DNS_LOOKUP_TIMEOUT_MS || 2500);

// TEST-ONLY escape hatch so the offline fixture (served on 127.0.0.1) can run.
// NEVER set this in a deployed/public environment. Read at call-time so tests
// can flip it after module import.
function allowPrivate() {
  return process.env.ALLOW_PRIVATE_TARGETS === "1";
}

// Only ordinary public unicast addresses are allowed. Everything else
// (loopback, private, linkLocal, uniqueLocal, reserved, CGNAT, broadcast,
// unspecified, ...) is denied. Using ipaddr's range() means new reserved
// ranges are denied by default rather than needing manual upkeep.
function ipIsBlocked(addr) {
  let parsed;
  try {
    parsed = ipaddr.parse(addr);
  } catch {
    return true; // unparseable → deny
  }
  // Treat IPv4-mapped IPv6 (::ffff:127.0.0.1) as its IPv4 form.
  if (parsed.kind() === "ipv6" && parsed.isIPv4MappedAddress()) {
    parsed = parsed.toIPv4MappedAddress
      ? parsed.toIPv4Address()
      : parsed.toIPv4Address();
  }
  return parsed.range() !== "unicast";
}

// Pull the bare host out of a URL. WHATWG `new URL()` already canonicalizes
// numeric IPv4 forms (octal/hex/decimal → dotted), closing that bypass.
// IPv6 hosts come wrapped in brackets, which we strip.
function hostFromUrl(rawUrl) {
  let u;
  try {
    u = new URL(rawUrl);
  } catch {
    return { error: true };
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return { nonHttp: true };
  }
  let host = u.hostname;
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  return { host };
}

async function resolveHostnameState(host, timeoutMs) {
  try {
    const addrs = await runWithTimeout(
      dns.promises.lookup(host, { all: true }),
      timeoutMs,
      "timeout"
    );

    if (addrs === "timeout") {
      return { blocked: true, reason: "unresolvable", detail: "timeout" };
    }
    if (!Array.isArray(addrs) || addrs.length === 0) {
      return { blocked: true, reason: "unresolvable", detail: "empty" };
    }
    if (addrs.some((a) => ipIsBlocked(a.address))) {
      return { blocked: true, reason: "private" };
    }
    return { blocked: false, reason: "public" };
  } catch (err) {
    return {
      blocked: true,
      reason: "unresolvable",
      detail: err?.code || err?.message || "lookup-failed",
    };
  }
}

export async function resolvePublicUrlState(rawUrl, options = {}) {
  if (allowPrivate()) return { blocked: false, reason: "public" };

  const { host, nonHttp, error } = hostFromUrl(rawUrl);
  if (error || !host) return { blocked: true, reason: "invalid" };
  if (nonHttp) return { blocked: false, reason: "nonHttp" };

  if (ipaddr.isValid(host)) {
    return ipIsBlocked(host) ? { blocked: true, reason: "private" } : { blocked: false, reason: "public" };
  }
  if (host === "localhost" || host.endsWith(".localhost")) {
    return { blocked: true, reason: "private" };
  }

  return resolveHostnameState(host, Number(options.lookupTimeoutMs || DNS_LOOKUP_TIMEOUT_MS));
}

/**
 * Cheap, synchronous check usable on every (sub)resource request: blocks the
 * request only if the host is a *literal* IP in a non-public range. Does not
 * resolve DNS. Non-http(s) and hostname-based requests pass (allowed to continue).
 */
export function isBlockedLiteral(rawUrl) {
  if (allowPrivate()) return false;
  const { host, nonHttp, error } = hostFromUrl(rawUrl);
  if (error) return true;
  if (nonHttp) return false; // data:/blob:/about: are fine to load
  if (!host) return true;
  if (ipaddr.isValid(host)) return ipIsBlocked(host);
  return false; // hostname → defer to the async DNS check
}

/**
 * Strict, async check for navigations (and pre-flight): resolves the hostname
 * and blocks if ANY resolved address is non-public. Catches DNS-based SSRF and
 * redirects to internal/metadata endpoints.
 */
export async function isBlockedUrl(rawUrl) {
  const state = await resolvePublicUrlState(rawUrl);
  return state.blocked;
}
