#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TARGET_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
: "${ROOTFS:?Set ROOTFS to the extracted R6700v3 rootfs directory}"
BIN=${BIN:-"$TARGET_DIR/build/fmst_nvram_guest"}

if [[ ! -x "$BIN" ]]; then
  echo "Binary not found: $BIN"
  echo "Run scripts/build.sh first."
  exit 1
fi

QEMU_ARGS=()
if [[ "${QEMU_STRACE:-0}" == "1" ]]; then
  QEMU_ARGS+=("-strace")
fi

exec qemu-arm-static "${QEMU_ARGS[@]}" -L "$ROOTFS" "$BIN"
