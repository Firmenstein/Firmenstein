# Build the self-contained MIPS-LE IIB demo guest.
#
# Requires a MIPS32 little-endian cross-compiler (not installed on the
# current dev host). Examples of usable toolchain triples:
#   - mipsel-linux-musl-gcc  (musl-cross-make; recommended)
#   - mipsel-linux-gnu-gcc   (Debian/Ubuntu gcc-mipsel-linux-gnu)
#   - mipsel-unknown-linux-musl-gcc (buildroot)
#
# -no-pie + -nostdlib + -nostartfiles + -ffreestanding yields an ET_EXEC
# ELF with every symbol at a fixed absolute VA. That lets the intervention
# manifest hard-code absolute addresses resolved with `readelf -s`.

CC ?= mipsel-linux-musl-gcc
OUT := fmst_mips_nvram_guest
SRC := fmst_mips_nvram_guest.c

CFLAGS := \
  -static \
  -nostdlib \
  -nostartfiles \
  -ffreestanding \
  -fno-builtin \
  -fno-stack-protector \
  -no-pie \
  -EL \
  -mabi=32 \
  -march=mips32r2 \
  -Wall -Wextra \
  -Wl,--entry=_start

.PHONY: all clean
all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<
	@echo "--- readelf -h ---"
	@readelf -h $@ | sed -n '1,12p'
	@echo "--- symbols ---"
	@readelf -s $@ | grep -E " (guarded_network_startup|apply_runtime_profile|sync_nvram_cache|nvram_init|nvram_get|nvram_set|nvram_commit|guest_main|_start) *$$"

clean:
	rm -f $(OUT)
