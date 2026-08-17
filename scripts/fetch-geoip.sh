#!/usr/bin/env bash
#
# Fetch the free DB-IP "IP-to-Country Lite" database for the dashboard's GeoIP map + country
# stats. DB-IP.com, CC BY 4.0 — attribution is shown in the dashboard footer. The file is NOT
# committed to the repo or baked into the published image; it lives in the storage volume.
#
#   scripts/fetch-geoip.sh                 # -> demo/storage/dbip-country.csv.gz
#
# After fetching, build the lookup table once: click "geoip" on the dashboard (admin), or
#   curl -X POST -H "X-Admin-Token: <pw>" 'http://HOST/?admin=geoip'
set -euo pipefail

DEST="${1:-$(cd "$(dirname "$0")/.." && pwd)/demo/storage}"
mkdir -p "$DEST"

# DB-IP publishes a fresh file each month; fall back to last month near the 1st.
for m in "$(date +%Y-%m)" "$(date -v-1m +%Y-%m 2>/dev/null || date -d 'last month' +%Y-%m)"; do
    url="https://download.db-ip.com/free/dbip-country-lite-${m}.csv.gz"
    echo "==> trying ${url}"
    if curl -fSL "$url" -o "$DEST/dbip-country.csv.gz"; then
        echo "==> saved ${DEST}/dbip-country.csv.gz ($(du -h "$DEST/dbip-country.csv.gz" | cut -f1))"
        echo "    build the table: POST /?admin=geoip with your admin token (or the dashboard button)."
        exit 0
    fi
done

echo "error: could not download the DB-IP lite database." >&2
exit 1
