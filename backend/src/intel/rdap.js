// Domain-age lookup via RDAP — free, no API key, open standard.
// https://www.rdap.net  /  https://about.rdap.org

/**
 * Look up the registration date and age (in days) for a hostname's domain.
 * Returns { domain, createdAt, ageDays } or { error } — never throws.
 */
export async function getDomainAge(hostname) {
  const domain = toRegistrableDomain(hostname);
  if (!domain) return { error: "no-domain" };

  try {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), 6000);
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { Accept: "application/rdap+json" },
      signal: controller.signal,
    });
    clearTimeout(t);

    if (!res.ok) return { domain, error: `rdap-${res.status}` };
    const data = await res.json();

    const reg = (data.events || []).find(
      (e) => e.eventAction === "registration"
    );
    if (!reg || !reg.eventDate) return { domain, error: "no-registration-event" };

    const createdAt = reg.eventDate;
    const ageDays = Math.floor(
      (Date.now() - new Date(createdAt).getTime()) / 86400000
    );
    return { domain, createdAt, ageDays };
  } catch (err) {
    return { domain, error: err.name === "AbortError" ? "timeout" : "fetch-failed" };
  }
}

// Naive registrable-domain extraction (good enough for a demo; ignores
// multi-part TLDs like .co.uk — swap in `tldts` later for accuracy).
function toRegistrableDomain(hostname) {
  if (!hostname) return null;
  const host = hostname.replace(/^www\./, "");
  const parts = host.split(".");
  if (parts.length <= 2) return host;
  return parts.slice(-2).join(".");
}
