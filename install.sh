#!/bin/sh
# Installs the latest publiclocal release: curl -fsSL https://raw.githubusercontent.com/sevenoways/publiclocal/main/install.sh | sh
# Set PUBLICLOCAL_VERSION=v0.2.0 to pin a version, BIN_DIR to choose where it goes.
set -eu

REPO=sevenoways/publiclocal
BIN_DIR=${BIN_DIR:-/usr/local/bin}

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux|darwin|freebsd) ;;
  *) echo "publiclocal: unsupported OS $os; download from https://github.com/$REPO/releases" >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo "publiclocal: unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac

version=${PUBLICLOCAL_VERSION:-$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest" | sed 's#.*/tag/##')}
file="publiclocal_${version#v}_${os}_${arch}.tar.gz"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading publiclocal $version for $os/$arch..."
curl -fsSL -o "$tmp/$file" "https://github.com/$REPO/releases/download/$version/$file"
curl -fsSL -o "$tmp/checksums.txt" "https://github.com/$REPO/releases/download/$version/checksums.txt"
(cd "$tmp" && grep " $file\$" checksums.txt | { sha256sum -c - 2>/dev/null || shasum -a 256 -c -; } >/dev/null) \
  || { echo "publiclocal: checksum mismatch" >&2; exit 1; }
tar -xzf "$tmp/$file" -C "$tmp" publiclocal

if [ -w "$BIN_DIR" ]; then
  mv "$tmp/publiclocal" "$BIN_DIR/publiclocal"
else
  sudo mv "$tmp/publiclocal" "$BIN_DIR/publiclocal"
fi
echo "Installed $("$BIN_DIR/publiclocal" version) to $BIN_DIR/publiclocal"
