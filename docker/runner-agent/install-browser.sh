#!/bin/sh
# Fetch the same official stable Chrome as agent-browser, without its fixed
# 120-second whole-download timeout. A stalled connection still times out.
set -eu

metadata=$(curl -fsSL --connect-timeout 30 --retry 3 \
  https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json)
version=$(printf '%s' "$metadata" | jq -er '.channels.Stable.version')
url=$(printf '%s' "$metadata" | jq -er '.channels.Stable.downloads.chrome[] | select(.platform == "linux64") | .url')
destination="$HOME/.agent-browser/browsers/chrome-$version"
archive=$(mktemp)
trap 'rm -f "$archive"' EXIT
curl -fL --connect-timeout 30 --speed-limit 1024 --speed-time 60 --retry 3 \
  --output "$archive" "$url"
mkdir -p "$destination"
unzip -q "$archive" -d "$destination"
"$destination/chrome-linux64/chrome" --version
