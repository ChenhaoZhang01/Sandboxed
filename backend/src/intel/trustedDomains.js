// Curated allowlist of well-known, high-reputation apex domains. A login page,
// redirect, or brand keyword on one of these is expected behaviour, not phishing
// — this is the "common sense" layer that stops e.g. mail.google.com being flagged.
//
// This is a hand-picked subset (covers every brand in detonate.js's impersonation
// list plus major sites). To make it exhaustive, swap in a real top-sites ranking
// (Tranco / Cisco Umbrella top-1M) loaded into the same Set — the lookup below is
// unchanged.
const TRUSTED_APEXES = new Set([
  // Google
  "google.com", "gmail.com", "googlemail.com", "youtube.com", "google.co.uk",
  // Microsoft
  "microsoft.com", "office.com", "office365.com", "live.com", "outlook.com",
  "msn.com", "bing.com", "windows.com", "xbox.com", "sharepoint.com",
  // Apple
  "apple.com", "icloud.com", "me.com",
  // Amazon
  "amazon.com", "aws.amazon.com", "amazon.co.uk", "primevideo.com",
  // Social / media
  "facebook.com", "instagram.com", "whatsapp.com", "messenger.com",
  "x.com", "twitter.com", "t.co", "linkedin.com", "reddit.com",
  "tiktok.com", "snapchat.com", "pinterest.com", "tumblr.com",
  "youtube.com", "twitch.tv", "discord.com", "telegram.org",
  // Streaming / consumer
  "netflix.com", "spotify.com", "hulu.com", "disneyplus.com",
  // Finance / payments
  "paypal.com", "coinbase.com", "binance.com", "metamask.io",
  "chase.com", "wellsfargo.com", "bankofamerica.com", "citi.com",
  "capitalone.com", "americanexpress.com", "usbank.com", "stripe.com",
  "venmo.com", "cash.app", "intuit.com", "turbotax.com",
  // Shopping
  "ebay.com", "walmart.com", "target.com", "etsy.com", "bestbuy.com",
  "aliexpress.com", "shopify.com",
  // Shipping / gov
  "usps.com", "ups.com", "fedex.com", "dhl.com", "irs.gov",
  // Dev / cloud / SaaS
  "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
  "cloudflare.com", "mozilla.org", "wikipedia.org", "wordpress.com",
  "dropbox.com", "box.com", "slack.com", "zoom.us", "notion.so",
  "atlassian.com", "salesforce.com", "adobe.com", "figma.com",
  "openai.com", "anthropic.com",
  // Search / portals
  "yahoo.com", "duckduckgo.com", "baidu.com",
]);

/**
 * True if `host` is, or is a subdomain of, a trusted apex domain.
 * Uses a strict suffix match so "notgoogle.com" / "google.com.evil.com" don't pass.
 */
export function isTrustedDomain(host) {
  if (!host) return false;
  const h = String(host).toLowerCase().replace(/\.$/, "");
  for (const apex of TRUSTED_APEXES) {
    if (h === apex || h.endsWith(`.${apex}`)) return true;
  }
  return false;
}
