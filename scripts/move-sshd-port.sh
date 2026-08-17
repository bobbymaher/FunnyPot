#!/usr/bin/env bash
#
# Move the host's real sshd off port 22 so the honeypot can serve SSH on 22 — in two phases so
# you can NEVER lock yourself out. Run from your Mac; uses scripts/deploy.env for the server.
#
#   scripts/move-sshd-port.sh add 2200
#       -> sshd now listens on BOTH 22 and 2200 (nothing lost yet).
#       -> THEN open 2200 inbound in the EC2 security group, and PROVE you can SSH in on 2200:
#            ssh -i <key> -p 2200 ec2-user@<host>
#   scripts/move-sshd-port.sh finalize 2200 --yes
#       -> removes port 22 from sshd (only after verifying 2200 listens). 22 is now free.
#       -> THEN redeploy the honeypot onto 22:
#            FUNNYPOT_SSH_PORT=2200 FUNNYPOT_SSH_ON_22=1 scripts/deploy.sh
#
# Works with either a sshd_config.d/ drop-in (Ubuntu 20.04+/AL2023) or a marked block in the
# main sshd_config (AL2 and older). It backs up the config, validates with `sshd -t` before
# every reload, and `add` never removes port 22 — so a bad edit can't lock you out.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/deploy.env" ]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/deploy.env"
fi

HOST="${FUNNYPOT_HOST:-}"
USER="${FUNNYPOT_USER:-ec2-user}"
KEY="${FUNNYPOT_KEY:-}"
CONN_PORT="${FUNNYPOT_SSH_PORT:-22}"   # port to reach the server on right now

ACTION="${1:-}"
PORT="${2:-}"
CONFIRM="${3:-}"

if [ -z "$HOST" ] || [ -z "$KEY" ] || [ -z "$ACTION" ] || [ -z "$PORT" ]; then
    echo "usage: scripts/move-sshd-port.sh add|finalize <port> [--yes]" >&2
    echo "  (needs FUNNYPOT_HOST + FUNNYPOT_KEY in scripts/deploy.env)" >&2
    exit 2
fi
if ! printf '%s' "$PORT" | grep -qE '^[0-9]+$' || [ "$PORT" = "22" ]; then
    echo "error: <port> must be a number other than 22." >&2
    exit 2
fi

echo "==> ${ACTION} sshd port ${PORT} on ${USER}@${HOST} (connecting on ${CONN_PORT})"

ssh -i "$KEY" -p "$CONN_PORT" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20 \
    "$USER@$HOST" "ACTION='$ACTION' PORT='$PORT' CONFIRM='$CONFIRM' bash -s" <<'REMOTE'
set -euo pipefail
MAIN=/etc/ssh/sshd_config
DROPDIR=/etc/ssh/sshd_config.d
DROP="$DROPDIR/00-funnypot-sshport.conf"
BEGIN='# >>> funnypot ssh port (managed) >>>'
END='# <<< funnypot ssh port (managed) <<<'

USE_DROPIN=0
if grep -qsE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d' "$MAIN"; then
    USE_DROPIN=1
fi

reload_sshd() {
    sudo sshd -t
    sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd 2>/dev/null \
        || sudo service sshd reload 2>/dev/null || sudo systemctl restart sshd
}

# An explicit uncommented "Port 22" outside our managed block?
explicit_22() {
    { grep -hsE '^[[:space:]]*Port[[:space:]]+22[[:space:]]*$' "$MAIN"; \
      grep -hsE '^[[:space:]]*Port[[:space:]]+22[[:space:]]*$' "$DROPDIR"/*.conf 2>/dev/null | grep -v funnypot; } \
        | grep -q . 2>/dev/null
}

# Build the port block. Keep 22 unless it is already explicitly configured elsewhere.
port_block() {
    local want_new="$1"
    if explicit_22; then
        printf 'Port %s\n' "$want_new"
    else
        printf 'Port 22\nPort %s\n' "$want_new"   # 22 is implicit -> assert it so we stay dual
    fi
}

if [ "$ACTION" = "add" ]; then
    if [ "$USE_DROPIN" = 1 ]; then
        sudo mkdir -p "$DROPDIR"
        port_block "$PORT" | sudo tee "$DROP" >/dev/null
    else
        sudo cp -n "$MAIN" "${MAIN}.funnypot.bak"
        sudo sed -i "/$BEGIN/,/$END/d" "$MAIN"
        { echo "$BEGIN"; port_block "$PORT"; echo "$END"; } | sudo tee -a "$MAIN" >/dev/null
    fi
    reload_sshd
    echo "OK: sshd now listens on 22 AND ${PORT} (both work — no lockout)."
    echo "NEXT: open ${PORT} inbound in the security group, SSH in on ${PORT} to VERIFY, then:"
    echo "      scripts/move-sshd-port.sh finalize ${PORT} --yes"

elif [ "$ACTION" = "finalize" ]; then
    if [ "$CONFIRM" != "--yes" ]; then
        echo "REFUSING: verify you can SSH in on ${PORT} first, then pass --yes." >&2
        exit 1
    fi
    if ! ss -tlnH 2>/dev/null | grep -qE "[:.]${PORT}[[:space:]]" && ! ss -tln 2>/dev/null | grep -qE "[:.]${PORT}([[:space:]]|$)"; then
        echo "ERROR: sshd is not listening on ${PORT} — run 'add' and verify before finalizing." >&2
        exit 1
    fi
    if [ "$USE_DROPIN" = 1 ]; then
        printf 'Port %s\n' "$PORT" | sudo tee "$DROP" >/dev/null
    else
        sudo sed -i "/$BEGIN/,/$END/d" "$MAIN"
        { echo "$BEGIN"; printf 'Port %s\n' "$PORT"; echo "$END"; } | sudo tee -a "$MAIN" >/dev/null
    fi
    # If port 22 is ALSO configured outside our block, comment it out so 22 is truly free.
    if explicit_22; then
        sudo cp -n "$MAIN" "${MAIN}.funnypot.bak"
        sudo sed -i 's/^\([[:space:]]*Port[[:space:]]\+22[[:space:]]*\)$/#\1  # funnypot: freed for honeypot/' "$MAIN"
    fi
    reload_sshd
    echo "OK: sshd now listens on ${PORT} only; port 22 is free for the honeypot."
    echo "NEXT: FUNNYPOT_SSH_PORT=${PORT} FUNNYPOT_SSH_ON_22=1 scripts/deploy.sh"
else
    echo "usage: add|finalize <port> [--yes]" >&2
    exit 2
fi
REMOTE
