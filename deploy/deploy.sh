#!/usr/bin/env bash
# Ship the committed HEAD to the NAS and restart the detector on it. Run from the repo root:
#   deploy/deploy.sh
#
# 1. Refuses a dirty tree: the NAS gets HEAD, so uncommitted work would silently stay behind.
# 2. Backs up data/state.db and data/alerts.jsonl as *.deploy-<time>.*, keeping this script's newest 5
#    of each (hand-made backups are never pruned).
# 3. Replaces the code with HEAD, deleting files HEAD no longer has. A plain `tar -x` over the old
#    tree leaves removed modules behind; data/ and .env are never touched.
# 4. Rebuilds the container and waits for Docker to report it healthy (deploy/hc.sh).
#
# DEPLOY_HOST, DEPLOY_KEY and DEPLOY_DIR override the author's NAS defaults below.
set -euo pipefail

HOST=${DEPLOY_HOST:-truenas_admin@192.168.18.134}
KEY=${DEPLOY_KEY:-$HOME/.ssh/truenas_dashboard_deploy}
DIR=${DEPLOY_DIR:-/mnt/Home/apps/pihole-detector}

nas() { ssh -i "$KEY" -o BatchMode=yes "$HOST" "$@"; }

if [ -n "$(git status --porcelain)" ]; then
    echo "deploy: uncommitted changes; commit them first (the NAS gets HEAD)" >&2
    exit 1
fi
rev=$(git rev-parse --short HEAD)
stamp=$(date +%Y-%m-%d-%H%M)

echo "deploy: backing up data/ on $HOST"
nas "set -e; cd '$DIR/data'
     for f in state.db alerts.jsonl; do
         [ -f \"\$f\" ] || continue
         sudo cp -p \"\$f\" \"\${f%.*}.deploy-$stamp.\${f##*.}\"
         ls -1t \"\${f%.*}\".deploy-*.\"\${f##*.}\" | tail -n +6 | xargs -r sudo rm -f
     done"

echo "deploy: shipping $rev"
git archive HEAD | nas "set -e; tmp=\$(mktemp -d); trap 'sudo rm -rf \"\$tmp\"' EXIT
    sudo tar -x -C \"\$tmp\"
    sudo rsync -a --delete --exclude=/data/ --exclude=/.env \"\$tmp/\" '$DIR/'
    cd '$DIR' && sudo docker compose -f deploy/compose.yml up -d --build --quiet-pull 2>&1 | tail -3"

echo "deploy: waiting for the healthcheck"
status=""
for _ in $(seq 1 30); do
    status=$(nas "sudo docker ps --filter name=pihole-detector --format '{{.Status}}'")
    case $status in
        *"(healthy)"*) echo "deploy: $rev is up: $status"; exit 0 ;;
    esac
    sleep 3
done
echo "deploy: not healthy after 90 s ($status); last log lines:" >&2
nas "sudo docker logs --tail 30 pihole-detector" >&2
exit 1
