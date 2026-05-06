#!/bin/bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/dist/native-amd64"
RELEASE_DIR="$ROOT_DIR/dist/release"
PKG_DIR="$OUT_DIR/package"

rm -rf "$OUT_DIR"
mkdir -p "$PKG_DIR/web" "$RELEASE_DIR"

echo "==> Build frontend"
cd "$ROOT_DIR/vite-frontend"
npm install --legacy-peer-deps
npm run build
cp -a dist/. "$PKG_DIR/web/"

echo "==> Build flux-core linux/amd64"
cd "$ROOT_DIR/flux-core"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$PKG_DIR/flux-core" .

echo "==> Build flux-agent linux/amd64"
cd "$ROOT_DIR/go-gost"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$RELEASE_DIR/flux-agent-amd64" .

echo "==> Package native release"
cp "$ROOT_DIR/install.sh" "$PKG_DIR/install.sh"
cp "$ROOT_DIR/README.md" "$PKG_DIR/README.md"
chmod +x "$PKG_DIR/flux-core" "$PKG_DIR/install.sh" "$RELEASE_DIR/flux-agent-amd64"

tar -czf "$RELEASE_DIR/flux-panel-native-amd64.tar.gz" -C "$PKG_DIR" .

echo "==> Done"
echo "$RELEASE_DIR/flux-panel-native-amd64.tar.gz"
echo "$RELEASE_DIR/flux-agent-amd64"
