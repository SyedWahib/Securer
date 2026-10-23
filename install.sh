#!/bin/sh
# Installs Securer into the current project: .securer/bin/securer, then runs `securer init`.
# Usage: curl -fsSL https://raw.githubusercontent.com/SyedWahib/Securer/main/install.sh | sh
#        curl -fsSL .../install.sh | sh -s -- claude codex     (only these agents)
set -eu

repo="SyedWahib/Securer"

# Inside a folder that already has Securer, reuse that install instead of downloading another copy.
if [ ! -d .securer ]; then
  d=$(pwd)
  while [ "$d" != / ]; do
    d=$(dirname "$d")
    if [ -x "$d/.securer/bin/securer" ]; then
      exec "$d/.securer/bin/securer" init "$@"
    fi
  done
fi

os=$(uname -s)
arch=$(uname -m)
case "$os-$arch" in
  Linux-x86_64) target=x86_64-unknown-linux-musl ;;
  Linux-aarch64 | Linux-arm64) target=aarch64-unknown-linux-musl ;;
  Darwin-x86_64) target=x86_64-apple-darwin ;;
  Darwin-arm64) target=aarch64-apple-darwin ;;
  *) echo "No prebuilt binary for $os $arch; build from source with: cargo build --release" >&2; exit 1 ;;
esac

if [ ! -d .git ] && [ "${SECURER_FORCE:-}" != 1 ]; then
  echo "Run this from the root of the project you want to protect (no .git here; set SECURER_FORCE=1 to continue anyway)." >&2
  exit 1
fi

mkdir -p .securer/bin
url="https://github.com/$repo/releases/latest/download/securer-$target.tar.gz"
echo "Downloading $url"
curl -fsSL "$url" | tar xz -C .securer/bin
chmod +x .securer/bin/securer
.securer/bin/securer init "$@"
