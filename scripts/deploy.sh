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

SSH_OPTS=(-i "$KEY" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=20)
PORTS="80 443 3000 4443 5000 8000 8008 8080 8081 8088 8090 8161 8443 8888 8983 9000 9090 9443 10443"

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
# \$HOME etc. expand on the REMOTE; \$PFLAGS expands locally.
# shellcheck disable=SC2029
ssh "${SSH_OPTS[@]}" "$USER@$HOST" "
    DATA_DIR=\"\$HOME/funnypot-data\"
    mkdir -p \"\$DATA_DIR\" && chmod 0777 \"\$DATA_DIR\"
    sudo docker rm -f funnypot 2>/dev/null || true
    sudo docker run -d --name funnypot --restart unless-stopped \
        -e FUNNYPOT_STYLE=realistic -v \"\$DATA_DIR\":/app/demo/storage $PFLAGS funnypot
    sudo docker ps --filter name=funnypot --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | head -3
    echo \"  logs on host: \$DATA_DIR/hits.log\"
"

echo "==> done. Test:  curl -I http://$HOST/   and   curl -Ik https://$HOST/"
echo "    Open the security group for the ports you want reachable (at least 80 + 443)."
