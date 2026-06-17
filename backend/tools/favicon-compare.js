import sharp from "sharp";
import fetch from "node-fetch";

async function fetchImageBuffer(urlOrBase64) {
  if (urlOrBase64.startsWith("data:")) {
    const [header, data] = urlOrBase64.split(",");
    if (!data) return null;
    // Skip SVG data URIs
    if (header.includes("svg")) return null;
    return Buffer.from(data, "base64");
  }

  try {
    const res = await fetch(urlOrBase64, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return null;

    const contentType = res.headers.get("content-type") ?? "";
    if (contentType.includes("svg") || contentType.includes("html") || contentType.includes("text")) return null;

    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length < 100) return null;

    // ICO files: Sharp doesn't support them, try extracting PNG chunk
    if (contentType.includes("icon") || urlOrBase64.endsWith(".ico")) {
      return extractPngFromIco(buf) ?? buf; // fall back to raw buf and let sharp try
    }

    return buf;
  } catch {
    return null;
  }
}

// ICO files are a header + directory + image data chunks
// PNG chunks inside ICO start with the PNG magic bytes
function extractPngFromIco(buf) {
  const PNG_MAGIC = Buffer.from([0x89, 0x50, 0x4e, 0x47]);
  const idx = buf.indexOf(PNG_MAGIC);
  if (idx === -1) return null;
  return buf.slice(idx);
}

async function faviconHash(urlOrBase64) {
  const buf = await fetchImageBuffer(urlOrBase64);
  if (!buf) return null;

  try {
    const { data } = await sharp(buf)
      .resize(8, 8, { fit: "fill" })
      .greyscale()
      .raw()
      .toBuffer({ resolveWithObject: true });

    const avg = data.reduce((s, v) => s + v, 0) / data.length;
    return data.reduce((hash, val, i) => {
      return hash | (BigInt(val >= avg ? 1 : 0) << BigInt(63 - i));
    }, 0n).toString(16).padStart(16, "0");
  } catch {
    return null;
  }
}

function hashDistance(a, b) {
  const diff = BigInt("0x" + a) ^ BigInt("0x" + b);
  return diff.toString(2).split("").filter((c) => c === "1").length;
}

export async function compareFavicons(urlA, urlB) {
  const [hashA, hashB] = await Promise.all([faviconHash(urlA), faviconHash(urlB)]);

  // If either favicon couldn't be fetched/parsed, can't compare
  if (!hashA || !hashB) return { hashA, hashB, distance: Infinity, likely_same: false };

  const distance = hashDistance(hashA, hashB);
  return { hashA, hashB, distance, likely_same: distance <= 10 };
}