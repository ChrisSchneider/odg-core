#!/usr/bin/env bash
set -euo pipefail

# Setup ODG
make setup

# Copy kubeconfig and point to host.docker.internal
ORIG=$HOME/.kube/config-orig
DEST=$HOME/.kube/config
if [[ -f "$ORIG" ]]; then
    mkdir -p "$(dirname "$DEST")"
    sed 's/127\.0\.0\.1/host.docker.internal/g' "$ORIG" > "$DEST"
    echo "Kubeconfig copied to $DEST (replacing 127.0.0.1 with host.docker.internal)"
fi