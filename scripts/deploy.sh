#!/usr/bin/env bash
#
# Deploy funnypot to your test server by building the image locally and shipping it over
# SSH — the server needs only the docker engine (from its distro repos), no buildx,
# compose plugin, or GitHub. Repeatable: re-run to rebuild + redeploy.
#
#   scripts/deploy.sh
#
# Server details live in scripts/deploy.env (gitignored — copy deploy.env.example).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [ -f "$SCRIPT_DIR/deploy.env" ]; then
    # shellcheck disable=SC1091
    . "$SCRIPT_DIR/deploy.env"
fi

HOST="${FUNNYPOT_HOST:-}"
USER="${FUNNYPOT_USER:-ec2-user}"
KEY="${FUNNYPOT_KEY:-}"
# EC2 is x86_64; build for that even on an Apple-Silicon Mac. Override if your box differs.
PLATFORM="${FUNNYPOT_PLATFORM:-linux/amd64}"
# Optional: hostname that gets a real Let's Encrypt cert (issued by scripts/letsencrypt.sh).
# When set, the container mounts the host cert store + ACME webroot and serves real HTTPS
# for this host once a cert exists. Empty = self-signed everywhere (unchanged behaviour).
LE_DOMAIN="${LE_DOMAIN:-}"

if [ -z "$HOST" ] || [ -z "$KEY" ]; then
    echo "error: FUNNYPOT_HOST and FUNNYPOT_KEY are not set." >&2
    echo "  cp scripts/deploy.env.example scripts/deploy.env  then edit it (it is gitignored)." >&2
    exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
    echo "error: local docker is required (this builds the image on your machine)." >&2
    echo "  install Docker Desktop, or wait for GitHub and use a server-side build." >&2
    exit 1
fi

# Port the host's real sshd listens on. Set FUNNYPOT_SSH_PORT once you've moved sshd off 22
# (scripts/move-sshd-port.sh) so the honeypot can take port 22 — otherwise deploy locks out.
SSH_PORT="${FUNNYPOT_SSH_PORT:-22}"
SSH_OPTS=(-i "$KEY" -p "$SSH_PORT" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20)
# Known HTTP + alt-HTTP + app/panel ports (nginx) plus the TCP protocol-honeypot ports (mail/cache/
# shell + databases + SCADA — see demo/entrypoint.sh). Keep in sync with demo/entrypoint.sh +
# demo/Dockerfile and open the matching inbound rules in the EC2 security group (the SG gates reachability).
PORTS="21 23 25 79 80 81 88 110 143 443 502 591 873 2082 2083 2086 2087 2095 2096 2181 2222 3000 3128 3306 3310 4433 4443 5000 5432 5601 5900 6379 7001 7070 7080 8000 8001 8008 8009 8080 8081 8082 8083 8088 8090 8161 8180 8443 8500 8834 8843 8880 8888 8983 9000 9080 9090 9200 9443 10000 10443 11211 27017 44818"

echo "==> [1/4] build image locally ($PLATFORM)"
docker build --platform "$PLATFORM" -f "$REPO_ROOT/demo/Dockerfile" -t funnypot "$REPO_ROOT"

echo "==> [2/4] ensure docker engine on $USER@$HOST"
ssh "${SSH_OPTS[@]}" "$USER@$HOST" 'bash -s' <<'REMOTE'
set -e
if ! command -v docker >/dev/null 2>&1; then
    echo "  installing docker..."
    if command -v dnf >/dev/null 2>&1; then sudo dnf install -y docker; else sudo yum install -y docker; fi
    sudo systemctl enable --now docker
fi
sudo systemctl start docker 2>/dev/null || true
REMOTE

echo "==> [3/4] ship image (~40 MB gzipped) + load on server"
docker save funnypot | gzip | ssh "${SSH_OPTS[@]}" "$USER@$HOST" 'gunzip | sudo docker load'

echo "==> [4/4] (re)start container (logs persisted to ~/funnypot-data on the host)"
PFLAGS=""
for p in $PORTS; do PFLAGS="$PFLAGS -p $p:$p"; done
# Serve the SSH honeypot on the real port 22 (host 22 -> container's ssh listener on 2222).
# Requires the host's own sshd to have vacated 22 first (scripts/move-sshd-port.sh) and
# FUNNYPOT_SSH_PORT set to the moved sshd port above.
if [ "${FUNNYPOT_SSH_ON_22:-0}" = "1" ]; then PFLAGS="$PFLAGS -p 22:2222"; fi
# \$HOME etc. expand on the REMOTE; \$PFLAGS expands locally.
# shellcheck disable=SC2029
ssh "${SSH_OPTS[@]}" "$USER@$HOST" "
    DATA_DIR=\"\$HOME/funnypot-data\"
    ACME_DIR=\"\$HOME/funnypot-acme\"
    mkdir -p \"\$DATA_DIR\" && chmod 0777 \"\$DATA_DIR\"
    mkdir -p \"\$ACME_DIR/.well-known/acme-challenge\"
    sudo mkdir -p /etc/letsencrypt
    sudo docker rm -f funnypot 2>/dev/null || true
    sudo docker run -d --name funnypot --restart unless-stopped \
        -e FUNNYPOT_STYLE=realistic \
        -e FUNNYPOT_LE_DOMAIN='$LE_DOMAIN' \
        -v \"\$DATA_DIR\":/app/demo/storage \
        -v \"\$ACME_DIR\":/var/acme:ro \
        -v /etc/letsencrypt:/etc/letsencrypt:ro \
        $PFLAGS funnypot
    sudo docker ps --filter name=funnypot --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | head -3
    echo \"  logs on host: \$DATA_DIR/hits.log\"
"

echo "==> done. Test:  curl -I http://$HOST/   and   curl -Ik https://$HOST/"
echo "    Open the security group for the ports you want reachable (at least 80 + 443)."
