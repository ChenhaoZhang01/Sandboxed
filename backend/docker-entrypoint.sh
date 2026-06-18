#!/bin/sh
set -e

# Best-effort signature refresh in the background — never blocks server
# startup (Fly's health check has a 20s grace period; freshclam's initial
# pull can take longer than that). The image already ships a DB baked in
# at build time, so scanning works immediately even if this fails or is
# still running when the first request arrives.
freshclam --quiet || echo "freshclam update failed, continuing with existing DB" >&2 &

exec node src/server.js
