#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TARGET_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
: "${ROOTFS:?Set ROOTFS to the extracted R6700v3 rootfs directory}"
OUT_DIR=${OUT_DIR:-"$TARGET_DIR/build"}
OUT_BIN=${OUT_BIN:-"$OUT_DIR/fmst_nvram_guest"}
MAP_FILE=${MAP_FILE:-"$OUT_DIR/fmst_nvram_guest.map"}

mkdir -p "$OUT_DIR"

arm-none-eabi-gcc \
  -nostdlib \
  -nostartfiles \
  -ffreestanding \
  -fno-builtin \
  -fno-stack-protector \
  -fno-pic \
  -marm \
  -march=armv5te \
  -I"$TARGET_DIR/include" \
  "$TARGET_DIR/src/entry.c" \
  "$TARGET_DIR/src/guest_main.c" \
  -L"$ROOTFS/lib" \
  -L"$ROOTFS/usr/lib" \
  -Wl,-rpath-link,"$ROOTFS/lib" \
  -Wl,-rpath-link,"$ROOTFS/usr/lib" \
  -Wl,--entry=_start \
  -Wl,--dynamic-linker=/lib/ld-uClibc.so.0 \
  -Wl,--no-as-needed \
  -Wl,-rpath,/lib:/usr/lib \
  -Wl,-Map,"$MAP_FILE" \
  -o "$OUT_BIN" \
  -Wl,-l:libnvram.so \
  -Wl,-l:libc.so.0

echo "Built $OUT_BIN"
readelf -h "$OUT_BIN" | sed -n '1,20p'
echo "---"
readelf -l "$OUT_BIN" | sed -n '1,40p'
echo "---"
readelf -d "$OUT_BIN" | sed -n '1,40p'
