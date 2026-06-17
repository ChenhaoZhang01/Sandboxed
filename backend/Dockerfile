# Containerized detonation engine. Each running container is a disposable
# sandbox — the "Sandboxed" isolation story. The official Puppeteer image
# ships a matching Chromium + all system deps, so nothing to wrangle.
# Tag MUST match the puppeteer version resolved in package-lock.json — the image
# ships the exact Chrome that puppeteer version expects. If you bump puppeteer,
# bump this tag to the same version or the cached Chrome won't match.
FROM ghcr.io/puppeteer/puppeteer:24.43.1

# The base image runs as the non-root `pptruser`.
WORKDIR /app

# Don't re-download Chromium; the image already ships it in Puppeteer's cache
# dir (PUPPETEER_CACHE_DIR is preset by the base image). Do NOT pin
# PUPPETEER_EXECUTABLE_PATH — this image installs Chrome under the cache dir,
# not /usr/bin, so puppeteer.launch() must resolve it itself.
ENV PUPPETEER_SKIP_DOWNLOAD=true \
    NODE_ENV=production

COPY --chown=pptruser:pptruser package*.json ./
RUN npm ci --omit=dev

COPY --chown=pptruser:pptruser . .

EXPOSE 8787
CMD ["node", "src/server.js"]
