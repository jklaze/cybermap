#!/bin/sh
# Downloads MaxMind GeoLite2-City and writes it to $GEOIP_DB_PATH.
# Requires MAXMIND_LICENSE_KEY (free, sign up at https://www.maxmind.com/en/geolite2/signup).
# Skips the download if a recent copy already exists.
set -eu

: "${MAXMIND_LICENSE_KEY:?MAXMIND_LICENSE_KEY is required. Get a free key at https://www.maxmind.com/en/geolite2/signup}"
: "${GEOIP_DB_PATH:=/geoip/GeoLite2-City.mmdb}"
: "${GEOIP_MAX_AGE_DAYS:=14}"

target_dir="$(dirname "$GEOIP_DB_PATH")"
mkdir -p "$target_dir"

if [ -f "$GEOIP_DB_PATH" ]; then
    if find "$GEOIP_DB_PATH" -mtime "-${GEOIP_MAX_AGE_DAYS}" -print -quit | grep -q .; then
        echo "[geoip-init] $GEOIP_DB_PATH is < ${GEOIP_MAX_AGE_DAYS} days old; skipping download"
        exit 0
    fi
    echo "[geoip-init] $GEOIP_DB_PATH is stale; refreshing"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

url="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz"
echo "[geoip-init] downloading GeoLite2-City..."
wget -qO "$tmpdir/db.tar.gz" "$url"

tar -xzf "$tmpdir/db.tar.gz" -C "$tmpdir"
mmdb="$(find "$tmpdir" -name 'GeoLite2-City.mmdb' -print -quit)"
if [ -z "$mmdb" ]; then
    echo "[geoip-init] ERROR: GeoLite2-City.mmdb not found in tarball" >&2
    exit 1
fi

mv "$mmdb" "$GEOIP_DB_PATH"
echo "[geoip-init] wrote $GEOIP_DB_PATH"
