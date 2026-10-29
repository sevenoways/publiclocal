#!/bin/sh
# Installs the latest rtun release: curl -fsSL https://raw.githubusercontent.com/sevenoways/rtun/main/install.sh | sh
# Set RTUN_VERSION=v0.1.1 to pin a version, BIN_DIR to choose where it goes.
set -eu

REPO=sevenoways/rtun
BIN_DIR=${BIN_DIR:-/usr/local/bin}

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux|darwin|freebsd) ;;
  *) echo "rtun: unsupported OS $os; download from https://github.com/$REPO/releases" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "rtun: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

version=${RTUN_VERSION:-$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed 's#.*/tag/##')}
file="rtun_${version#v}_${os}_${arch}.tar.gz"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading rtun $version for $os/$arch..."
curl -fsSL -o "$tmp/$file" "https://github.com/$REPO/releases/download/$version/$file"
curl -fsSL -o "$tmp/checksums.txt" "https://github.com/$REPO/releases/download/$version/checksums.txt"
(cd "$tmp" && grep " $file\$" checksums.txt | { sha256sum -c - 2>/dev/null || shasum -a 256 -c -; } >/dev/null) \
  || { echo "rtun: checksum mismatch" >&2; exit 1; }
tar -xzf "$tmp/$file" -C "$tmp" rtun

if [ -w "$BIN_DIR" ]; then
  mv "$tmp/rtun" "$BIN_DIR/rtun"
else
  sudo mv "$tmp/rtun" "$BIN_DIR/rtun"
fi
echo "Installed $("$BIN_DIR/rtun" version) to $BIN_DIR/rtun"
