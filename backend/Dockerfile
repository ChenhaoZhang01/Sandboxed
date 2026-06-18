# Containerized detonation engine. Each running container is a disposable
# sandbox — the "Sandboxed" isolation story. The official Puppeteer image
# ships a matching Chromium + all system deps, so nothing to wrangle.
# Tag MUST match the puppeteer version resolved in package-lock.json — the image
# ships the exact Chrome that puppeteer version expects. If you bump puppeteer,
# bump this tag to the same version or the cached Chrome won't match.
FROM ghcr.io/puppeteer/puppeteer:24.43.1

USER root

# Install ClamAV tooling locally. The app prefers a local clamd daemon over
# 127.0.0.1:3310, but can fall back to the clamscan binary if the daemon is not
# reachable.
# freshclam is run at build time so the container starts quickly at runtime.
RUN apt-get update \
    && apt-get install -y --no-install-recommends clamav clamav-daemon clamav-freshclam \
    && freshclam --stdout || true \
    && rm -rf /var/lib/apt/lists/*

# clamd and the runtime freshclam fallback (see docker-entrypoint.sh) run as the
# non-root pptruser, so the signature DB dir must be writable by it.
RUN mkdir -p /var/lib/clamav /run/clamav \
    && chown -R pptruser:pptruser /var/lib/clamav /run/clamav

WORKDIR /app

# Don't re-download Chromium; the image already ships it in Puppeteer's cache
# dir (PUPPETEER_CACHE_DIR is preset by the base image). Do NOT pin
# PUPPETEER_EXECUTABLE_PATH — this image installs Chrome under the cache dir,
# not /usr/bin, so puppeteer.launch() must resolve it itself.
ENV PUPPETEER_SKIP_DOWNLOAD=true \
    NODE_ENV=production \
    CLAMD_HOST=127.0.0.1 \
    CLAMD_PORT=3310

COPY --chown=pptruser:pptruser package*.json ./
RUN npm ci --omit=dev

COPY --chown=pptruser:pptruser . .
COPY --chown=pptruser:pptruser docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

EXPOSE 8787
USER pptruser
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "src/server.js"]
