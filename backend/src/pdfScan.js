import { writeFile, unlink } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";
import path from "node:path";
import NodeClam from "clamscan";

const CLAMD_SOCKET = process.env.CLAMD_SOCKET || "/var/run/clamav/clamd.ctl";
const CLAMD_HOST = process.env.CLAMD_HOST || "";
const CLAMD_PORT = Number(process.env.CLAMD_PORT || 3310);
const CLAM_INIT_TIMEOUT_MS = Number(process.env.CLAM_INIT_TIMEOUT_MS || 5000);
const CLAMSCAN_BIN = process.env.CLAMSCAN_BIN || "/usr/bin/clamscan";
const CLAMSCAN_LOCAL_FALLBACK = process.env.CLAMSCAN_LOCAL_FALLBACK === "1";

let clamscanPromise = null;
let clamdInitWarned = false;

function hasScannerBackend() {
  return !!CLAMD_HOST || existsSync(CLAMD_SOCKET) || (CLAMSCAN_LOCAL_FALLBACK && existsSync(CLAMSCAN_BIN));
}

async function getClamscan() {
  if (!hasScannerBackend()) {
    return null;
  }
  if (!clamscanPromise) {
    clamscanPromise = new NodeClam()
      .init({
        removeInfected: false,
        clamscan: {
          path: CLAMSCAN_BIN,
          active: true,
        },
        clamdscan: {
          socket: CLAMD_HOST ? false : CLAMD_SOCKET,
          host: CLAMD_HOST || false,
          port: CLAMD_HOST ? CLAMD_PORT : false,
          timeout: CLAM_INIT_TIMEOUT_MS,
          localFallback: CLAMSCAN_LOCAL_FALLBACK,
        },
        preference: "clamdscan",
      })
      .catch((err) => {
        if (!clamdInitWarned) {
          console.warn("ClamAV unavailable (scanning will be unavailable):", err.message || err);
          clamdInitWarned = true;
        }
        clamscanPromise = null; // allow retry on a later call once clamd is back
        return null;
      });
  }
  return clamscanPromise;
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
    const { isInfected, viruses } = await clamscan.isInfected(tempPath);
    return isInfected ? { status: "infected", viruses: viruses || [] } : { status: "clean" };
  } catch (err) {
    console.error("ClamAV scan failed:", err.message || err);
    return { status: "error", message: String(err.message || err) };
  } finally {
    await unlink(tempPath).catch(() => {});
  }
}
