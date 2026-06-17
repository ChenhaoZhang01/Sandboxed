import { readFile } from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Same file the /verified-links endpoints in server.js read/write.
const VERIFIED_LINKS_PATH = path.join(__dirname, "../../verifiedLinks.json");

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
  } catch {
    return null;
  }
}

/**
 * True if `host` matches (or is a subdomain of) a host the user has explicitly
 * marked verified. Never throws — a missing/garbled file just means "not verified".
 */
export async function isVerifiedHost(host) {
  if (!host) return false;
  const h = String(host).toLowerCase().replace(/^www\./, "").replace(/\.$/, "");

  let entries;
  try {
    entries = JSON.parse(await readFile(VERIFIED_LINKS_PATH, "utf8"));
  } catch {
    return false;
  }
  if (!Array.isArray(entries)) return false;

  for (const entry of entries) {
    const vh = hostOf(entry?.url);
    if (vh && (h === vh || h.endsWith(`.${vh}`))) return true;
  }
  return false;
}
