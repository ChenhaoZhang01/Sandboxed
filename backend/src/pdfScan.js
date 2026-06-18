import { writeFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import path from "node:path";
import NodeClam from "clamscan";

// Daemon mode (clamdscan) is opt-in via CLAMD_SOCKET/CLAMD_HOST — useful for
// local dev against a Homebrew/system clamd. Production sets neither, so it
// defaults to the standalone `clamscan` binary (installed in Dockerfile),
// which loads the virus DB per-scan instead of holding it in memory all the
// time. No persistent daemon means no idle RAM cost on the 1GB VM that also
// runs a live Chromium instance — but it also means no daemon-side timeout,
// hence CLAM_SCAN_TIMEOUT_MS below.
const CLAMD_SOCKET = process.env.CLAMD_SOCKET || "";
const CLAMD_HOST = process.env.CLAMD_HOST || "";
const CLAMD_PORT = Number(process.env.CLAMD_PORT || 3310);
const CLAM_INIT_TIMEOUT_MS = Number(process.env.CLAM_INIT_TIMEOUT_MS || 5000);
const CLAM_SCAN_TIMEOUT_MS = Number(process.env.CLAM_SCAN_TIMEOUT_MS || 30000);
const CLAMSCAN_BIN = process.env.CLAMSCAN_BIN || "/usr/bin/clamscan";
const USE_DAEMON = Boolean(CLAMD_SOCKET || CLAMD_HOST);

let clamscanPromise = null;

async function getClamscan() {
  if (!clamscanPromise) {
    clamscanPromise = new NodeClam()
      .init({
        removeInfected: false,
        clamscan: {
          path: CLAMSCAN_BIN,
          active: !USE_DAEMON,
        },
        clamdscan: {
          socket: CLAMD_HOST ? false : (CLAMD_SOCKET || false),
          host: CLAMD_HOST || false,
          port: CLAMD_HOST ? CLAMD_PORT : false,
          timeout: CLAM_INIT_TIMEOUT_MS,
          localFallback: false,
          active: USE_DAEMON,
        },
        preference: USE_DAEMON ? "clamdscan" : "clamscan",
      })
      .catch((err) => {
        console.error("ClamAV init failed (scanning will be unavailable):", err.message || err);
        clamscanPromise = null; // allow retry on a later call once clamd is back
        return null;
      });
  }
  return clamscanPromise;
}

function withTimeout(promise, ms, message) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(message)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/**
 * @param {Buffer} buffer
 * @param {string} [ext] temp-file extension (ClamAV scans content regardless; this
 *   only affects the throwaway temp filename). Defaults to ".bin".
 * @returns {Promise<{status: "clean"|"infected"|"unavailable"|"error", viruses?: string[], message?: string}>}
 */
export async function scanBuffer(buffer, ext = ".bin") {
  const clamscan = await getClamscan();
  if (!clamscan) {
    return { status: "unavailable", message: "ClamAV daemon is not reachable." };
  }

  const tempPath = path.join(tmpdir(), `sandboxer-${randomUUID()}${ext}`);
  try {
    await writeFile(tempPath, buffer);
    const { isInfected, viruses } = await withTimeout(
      clamscan.isInfected(tempPath),
      CLAM_SCAN_TIMEOUT_MS,
      `ClamAV scan timed out after ${CLAM_SCAN_TIMEOUT_MS}ms`
    );
    return isInfected ? { status: "infected", viruses: viruses || [] } : { status: "clean" };
  } catch (err) {
    console.error("ClamAV scan failed:", err.message || err);
    return { status: "error", message: String(err.message || err) };
  } finally {
    await unlink(tempPath).catch(() => {});
  }
}
