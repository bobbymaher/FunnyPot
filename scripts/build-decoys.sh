#!/usr/bin/env bash
#
# Build the decoy archives the demo honeypot serves for .zip / .tar.gz probes on paths that
# would otherwise 404. Each is a NESTED archive: peel a layer, find another archive, repeat —
# down to a fake .env / credentials at the bottom. Bounded and safe, NOT a decompression bomb:
#   - fixed depth (DEPTH layers), so recursion always terminates;
#   - every layer is a normal archive of the next (already-compressed → stored, no
#     amplification), so the fully-extracted total stays a few KB, not gigabytes;
#   - the script asserts the outer file is small before writing it.
# It wastes an attacker's *time* (manual re-extraction), never their RAM/disk.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$SCRIPT_DIR/../demo/decoys"
DEPTH="${DECOY_DEPTH:-12}"
MAX_BYTES="${DECOY_MAX_BYTES:-524288}" # 512 KB ceiling on the served file

mkdir -p "$OUT_DIR"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Enticing per-layer archive names so a human keeps digging.
NAMES=(backup_full db_backup_final website_backup account_dump prod_snapshot \
       config_archive vault_export secrets_bundle db_prod home_backup wp_backup archive)

# --- innermost payload: fabricated, obviously-inert secrets + a plain-English notice. ---
seed_payload() {
    local dir="$1"
    cat > "$dir/.env" <<'ENV'
APP_ENV=production
APP_KEY=base64:0000000000000000000000000000000000000000000=
DB_HOST=127.0.0.1
DB_USERNAME=admin
DB_PASSWORD=0000000000000000000000000000
ENV
    cat > "$dir/credentials.txt" <<'CREDS'
AWS_ACCESS_KEY_ID=AKIA0000000000000000
AWS_SECRET_ACCESS_KEY=0000000000000000000000000000000000000000
CREDS
    cat > "$dir/NOTICE.txt" <<'NOTE'
This archive was served by a honeypot. Every value inside it is fabricated
and useless. There was never any real data here. Your request has been logged.
NOTE
}

layer_readme() {
    printf 'Full backup split across the enclosed archive. Continue unpacking.\n' > "$1/README.txt"
}

build_nest() {
    local kind="$1"          # zip | targz
    local pack="$2"          # function name to pack a dir -> file
    local ext="$3"

    local inner="$WORK/${kind}-payload"
    mkdir -p "$inner"
    seed_payload "$inner"

    local cur="$WORK/${kind}-l0.$ext"
    "$pack" "$inner" "$cur"

    local i name layerdir next
    for (( i = 1; i <= DEPTH; i++ )); do
        name="${NAMES[$(( (i - 1) % ${#NAMES[@]} ))]}"
        layerdir="$WORK/${kind}-layer$i"
        mkdir -p "$layerdir"
        mv "$cur" "$layerdir/${name}.$ext"
        layer_readme "$layerdir"
        next="$WORK/${kind}-l$i.$ext"
        "$pack" "$layerdir" "$next"
        cur="$next"
    done

    local size
    size="$(wc -c < "$cur" | tr -d ' ')"
    if [ "$size" -gt "$MAX_BYTES" ]; then
        echo "ERROR: $kind decoy is ${size} bytes (> ${MAX_BYTES}). Refusing — check DEPTH/payload." >&2
        exit 1
    fi
    cp "$cur" "$OUT_DIR/backup.$ext"
    echo "  backup.$ext: ${size} bytes, ${DEPTH} nested layers"
}

pack_zip() {   # dir file  — store the (incompressible) inner archive; -X strips extra metadata
    ( cd "$1" && zip -qrX "$2" . )
}
pack_targz() { # dir file
    ( cd "$1" && tar czf "$2" . )
}

echo "==> building nested decoys (DEPTH=$DEPTH) -> $OUT_DIR"
build_nest zip pack_zip zip
build_nest targz pack_targz tar.gz
echo "==> done."
