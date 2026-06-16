# Containerized detonation engine. Each running container is a disposable
# sandbox — the "ShadowBox" isolation story. The official Puppeteer image
# ships a matching Chromium + all system deps, so nothing to wrangle.
FROM ghcr.io/puppeteer/puppeteer:24.10.0

# The base image runs as the non-root `pptruser`.
WORKDIR /app

# Don't re-download Chromium; the image already has it.
ENV PUPPETEER_SKIP_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/google-chrome-stable \
    NODE_ENV=production

COPY --chown=pptruser:pptruser package*.json ./
RUN npm ci --omit=dev

COPY --chown=pptruser:pptruser . .

EXPOSE 8787
CMD ["node", "src/server.js"]
