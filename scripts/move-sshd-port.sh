#!/usr/bin/env bash
#
# Move the host's real sshd off port 22 so the honeypot can serve SSH on 22 — in two phases so
# you can NEVER lock yourself out. Run from your Mac; uses scripts/deploy.env for the server.
#
#   scripts/move-sshd-port.sh add 2200
#       -> sshd now listens on BOTH 22 and 2200 (nothing lost yet).
#       -> THEN: open 2200 inbound in the EC2 security group, and prove you can SSH in on 2200:
#            ssh -i <key> -p 2200 ec2-user@<host>
#   scripts/move-sshd-port.sh finalize 2200 --yes
#       -> removes port 22 from sshd (only after verifying 2200 listens). 22 is now free.
#       -> THEN redeploy the honeypot onto 22:
#            FUNNYPOT_SSH_PORT=2200 FUNNYPOT_SSH_ON_22=1 scripts/deploy.sh
#
# Uses drop-in /etc/ssh/sshd_config.d/ (Ubuntu 20.04+/AL2023); errors out if the host doesn't
# use drop-ins, so it never blindly rewrites the main sshd_config.
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
DROP=/etc/ssh/sshd_config.d/00-funnypot-sshport.conf

if ! grep -qsE '^\s*Include\s+/etc/ssh/sshd_config\.d' /etc/ssh/sshd_config; then
    echo "ERROR: this host's sshd_config has no drop-in Include; move the port by hand to avoid a bad edit." >&2
    exit 1
fi

reload_sshd() {
    sudo sshd -t
    sudo systemctl reload ssh 2>/dev/null || sudo systemctl reload sshd 2>/dev/null || sudo systemctl restart sshd
}

if [ "$ACTION" = "add" ]; then
    printf 'Port 22\nPort %s\n' "$PORT" | sudo tee "$DROP" >/dev/null
    reload_sshd
    echo "OK: sshd now listens on 22 AND ${PORT} (both work — no lockout)."
    echo "NEXT: open ${PORT} inbound in the security group, SSH in on ${PORT} to VERIFY, then:"
    echo "      scripts/move-sshd-port.sh finalize ${PORT} --yes"
elif [ "$ACTION" = "finalize" ]; then
    if [ "$CONFIRM" != "--yes" ]; then
        echo "REFUSING: verify you can SSH in on ${PORT} first, then pass --yes." >&2
        exit 1
    fi
    if ! ss -tlnH 2>/dev/null | grep -qE "[:.]${PORT}\b" && ! ss -tln 2>/dev/null | grep -qE "[:.]${PORT}\b"; then
        echo "ERROR: sshd is not listening on ${PORT} — run 'add' and verify before finalizing." >&2
        exit 1
    fi
    printf 'Port %s\n' "$PORT" | sudo tee "$DROP" >/dev/null
    reload_sshd
    echo "OK: sshd now listens on ${PORT} only; port 22 is free for the honeypot."
    echo "NEXT: FUNNYPOT_SSH_PORT=${PORT} FUNNYPOT_SSH_ON_22=1 scripts/deploy.sh"
else
    echo "usage: add|finalize <port> [--yes]" >&2
    exit 2
fi
REMOTE
