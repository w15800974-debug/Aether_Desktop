#!/usr/bin/env bash
set -euo pipefail

# Build Aether Desktop for Ubuntu (24.04 / 26.x) x86_64 (.deb & AppImage)
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PSIPHON_VERSION="${PSIPHON_VERSION:-83aa73b9b982e7421e00117f5b0c5aceb5dda452}"
LYREBIRD_VERSION="${LYREBIRD_VERSION:-lyrebird-0.6.1}"
XRAY_VERSION="${XRAY_VERSION:-v25.12.8}"
TOR_BUNDLE_VERSION="${TOR_BUNDLE_VERSION:-14.5.2}"

echo "==> Checking Ubuntu build dependencies..."
for cmd in cargo rustc node npm go curl unzip tar dpkg-deb; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required tool: $cmd"
    echo "Install Ubuntu deps with:"
    echo "  sudo apt-get update && sudo apt-get install -y libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf libssl-dev pkg-config build-essential cmake clang protobuf-compiler dpkg-dev curl unzip golang-go nodejs npm"
    exit 1
  fi
done

mkdir -p dist-engine/xray dist-engine/tor dist-engine/pt

echo "==> Building Aether Core (Linux x64)..."
cargo build --release --manifest-path native/aether/aether/Cargo.toml
cp native/aether/aether/target/release/aether dist-engine/aether
chmod +x dist-engine/aether

echo "==> Building Psiphon Tunnel Core (Linux x64)..."
if [ ! -x dist-engine/psiphon-tunnel-core ]; then
  TMP_PSI="$(mktemp -d)"
  git clone https://github.com/Psiphon-Labs/psiphon-tunnel-core.git "$TMP_PSI"
  git -C "$TMP_PSI" checkout "$PSIPHON_VERSION"
  (cd "$TMP_PSI/ConsoleClient" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "$ROOT_DIR/dist-engine/psiphon-tunnel-core" .)
  chmod +x dist-engine/psiphon-tunnel-core
  rm -rf "$TMP_PSI"
fi
touch dist-engine/server_entries.txt

echo "==> Building lyrebird pluggable transport (Linux x64)..."
if [ ! -x dist-engine/pt/lyrebird ]; then
  TMP_LYR="$(mktemp -d)"
  git clone --depth 1 --branch "$LYREBIRD_VERSION" https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird.git "$TMP_LYR"
  (cd "$TMP_LYR" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "${ROOT_DIR}/dist-engine/pt/lyrebird" ./cmd/lyrebird)
  chmod +x dist-engine/pt/lyrebird
  rm -rf "$TMP_LYR"
fi

cat << 'EOF' > dist-engine/pt/pt_config.json
{
  "pluggableTransports": {
    "lyrebird": "ClientTransportPlugin meek_lite,obfs2,obfs3,obfs4,scramblesuit,webtunnel exec ${pt_path}lyrebird",
    "snowflake": "ClientTransportPlugin snowflake exec ${pt_path}lyrebird"
  }
}
EOF

echo "==> Staging Xray-core ${XRAY_VERSION} (Linux x64)..."
if [ ! -x dist-engine/xray/xray ]; then
  curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip" -o /tmp/aether-xray.zip
  unzip -j -o /tmp/aether-xray.zip xray -d dist-engine/xray/
  chmod +x dist-engine/xray/xray
  rm -f /tmp/aether-xray.zip
fi

echo "==> Staging Tor Expert Bundle ${TOR_BUNDLE_VERSION} (Linux x64)..."
if [ ! -x dist-engine/tor/tor ]; then
  TMP_TOR="$(mktemp -d)"
  curl -fsSL "https://archive.torproject.org/tor-package-archive/torbrowser/${TOR_BUNDLE_VERSION}/tor-expert-bundle-linux-x86_64-${TOR_BUNDLE_VERSION}.tar.gz" -o "$TMP_TOR/tor.tar.gz"
  tar -xzf "$TMP_TOR/tor.tar.gz" -C "$TMP_TOR"
  cp "$TMP_TOR/tor/tor" dist-engine/tor/tor
  cp "$TMP_TOR/data/geoip" dist-engine/tor/geoip
  cp "$TMP_TOR/data/geoip6" dist-engine/tor/geoip6
  chmod +x dist-engine/tor/tor
  rm -rf "$TMP_TOR"
fi

echo "==> Installing npm dependencies & building .deb / AppImage..."
npm ci
export APP_PATCHLEVEL="$(cat PATCHLEVEL 2>/dev/null || echo '1.4.0-linux')"
npm run tauri build -- --bundles deb,appimage

echo "==> Done! Packages are in src-tauri/target/release/bundle/deb/ and appimage/"
