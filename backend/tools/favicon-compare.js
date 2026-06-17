// favicon-compare.js
import sharp from "sharp";
import fetch from "node-fetch"
// Resize to 8x8 greyscale, return 64-bit average hash string
async function faviconHash(urlOrBase64) {
  const buf = urlOrBase64.startsWith("data:")
    ? Buffer.from(urlOrBase64.split(",")[1], "base64")
    : await fetch(urlOrBase64).then((r) => r.arrayBuffer()).then(Buffer.from);

  const { data } = await sharp(buf)
    .resize(8, 8, { fit: "fill" })
    .greyscale()
    .raw()
    .toBuffer({ resolveWithObject: true });

  const avg = data.reduce((s, v) => s + v, 0) / data.length;
  return data.reduce((hash, val, i) => {
    return hash | (BigInt(val >= avg ? 1 : 0) << BigInt(63 - i));
  }, 0n).toString(16).padStart(16, "0");
}

// Hamming distance between two hex hash strings (0 = identical, 64 = opposite)
function hashDistance(a, b) {
  const diff = BigInt("0x" + a) ^ BigInt("0x" + b);
  return diff.toString(2).split("").filter((c) => c === "1").length;
}

export async function compareFavicons(urlA, urlB) {
  const [hashA, hashB] = await Promise.all([faviconHash(urlA), faviconHash(urlB)]);
  const distance = hashDistance(hashA, hashB);
  return { hashA, hashB, distance, likely_same: distance <= 10 };
}