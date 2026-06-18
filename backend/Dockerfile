# Containerized detonation engine. Each running container is a disposable
# sandbox — the "Sandboxed" isolation story. The official Puppeteer image
# ships a matching Chromium + all system deps, so nothing to wrangle.
# Tag MUST match the puppeteer version resolved in package-lock.json — the image
# ships the exact Chrome that puppeteer version expects. If you bump puppeteer,
# bump this tag to the same version or the cached Chrome won't match.
FROM ghcr.io/puppeteer/puppeteer:24.43.1

# The base image runs as the non-root `pptruser`.
WORKDIR /app

# ClamAV: standalone `clamscan` CLI + `freshclam` updater only — no
# persistent `clamd` daemon (see pdfScan.js, which calls the binary
# per-scan). That keeps idle RAM at zero on this 1GB VM, which already runs
# a live Chromium instance for the core detonation feature; a resident
# clamd needs ~3-4GB on its own and isn't safe to run alongside it here.
# Needs root for apt-get and to seed the signature DB; Debian's package
# ships freshclam.conf with a literal "Example" line that must be removed
# before freshclam will run. chown so pptruser (the runtime user) can read
# and refresh the DB later.
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends clamav \
    && rm -rf /var/lib/apt/lists/* \
    && sed -i '/^Example/d' /etc/clamav/freshclam.conf \
    && freshclam \
    && chown -R pptruser:pptruser /var/lib/clamav /etc/clamav
USER pptruser

# Don't re-download Chromium; the image already ships it in Puppeteer's cache
# dir (PUPPETEER_CACHE_DIR is preset by the base image). Do NOT pin
# PUPPETEER_EXECUTABLE_PATH — this image installs Chrome under the cache dir,
# not /usr/bin, so puppeteer.launch() must resolve it itself.
ENV PUPPETEER_SKIP_DOWNLOAD=true \
    NODE_ENV=production

COPY --chown=pptruser:pptruser package*.json ./
RUN npm ci --omit=dev

COPY --chown=pptruser:pptruser . .
RUN chmod +x docker-entrypoint.sh

EXPOSE 8787
ENTRYPOINT ["./docker-entrypoint.sh"]
