#!/usr/bin/env bash
set -euo pipefail

CLAMD_HOST="${CLAMD_HOST:-127.0.0.1}"
CLAMD_PORT="${CLAMD_PORT:-3310}"
CLAMD_CONF="/tmp/clamd.conf"
CLAMD_BIN="${CLAMD_BIN:-/usr/sbin/clamd}"

if [ ! -x "$CLAMD_BIN" ] && command -v clamd >/dev/null 2>&1; then
  CLAMD_BIN="$(command -v clamd)"
fi

if [ -x "$CLAMD_BIN" ]; then
  cp /etc/clamav/clamd.conf "$CLAMD_CONF"
  sed -i \
    -e 's|^#\?Foreground .*|Foreground true|' \
    -e 's|^#\?LogFile .*|LogFile /dev/stdout|' \
    -e 's|^#\?LogTime .*|LogTime true|' \
    -e 's|^#\?DatabaseDirectory .*|DatabaseDirectory /var/lib/clamav|' \
    -e 's|^#\?TCPSocket .*|TCPSocket '"$CLAMD_PORT"'|' \
    -e 's|^#\?TCPAddr .*|TCPAddr '"$CLAMD_HOST"'|' \
    -e 's|^#\?User .*|User pptruser|' \
    -e 's|^#\?LocalSocket .*|LocalSocket /tmp/clamd.ctl|' \
    -e 's|^#\?PidFile .*|PidFile /tmp/clamd.pid|' \
    -e 's|^#\?TemporaryDirectory .*|TemporaryDirectory /tmp|' \
    -e 's|^#\?ConcurrentDatabaseReload .*|ConcurrentDatabaseReload no|' \
    "$CLAMD_CONF"

  if ! grep -q '^TCPSocket ' "$CLAMD_CONF"; then
    echo "TCPSocket $CLAMD_PORT" >> "$CLAMD_CONF"
  fi
  if ! grep -q '^TCPAddr ' "$CLAMD_CONF"; then
    echo "TCPAddr $CLAMD_HOST" >> "$CLAMD_CONF"
  fi
  if ! grep -q '^User ' "$CLAMD_CONF"; then
    echo "User pptruser" >> "$CLAMD_CONF"
  fi
  # Loading a second copy of the DB during a reload nearly doubles clamd's RAM;
  # disable it so a memory-constrained VM doesn't OOM the daemon mid-reload.
  if ! grep -q '^ConcurrentDatabaseReload ' "$CLAMD_CONF"; then
    echo "ConcurrentDatabaseReload no" >> "$CLAMD_CONF"
  fi

  # The build-time freshclam uses "|| true", so a failed download (network /
  # rate-limit) silently ships an image with NO signature database. clamd then
  # refuses to start and every scan reports "Could not scan via TCP or locally".
  # Fetch the DB now if it's missing so the container is self-healing.
  if ! ls /var/lib/clamav/*.cvd /var/lib/clamav/*.cld >/dev/null 2>&1; then
    echo "No ClamAV signature database found; running freshclam..." >&2
    freshclam --stdout || echo "freshclam failed; scanning may be unavailable" >&2
  fi

  "$CLAMD_BIN" --config-file="$CLAMD_CONF" &
  CLAMD_PID=$!

  for _ in $(seq 1 30); do
    if (echo > "/dev/tcp/$CLAMD_HOST/$CLAMD_PORT") >/dev/null 2>&1; then
      break
    fi
    if ! kill -0 "$CLAMD_PID" >/dev/null 2>&1; then
      echo "ClamAV daemon exited during startup; scanning will be unavailable" >&2
      break
    fi
    sleep 1
  done
else
  echo "ClamAV daemon binary not found; scanning will be unavailable" >&2
fi

exec "$@"