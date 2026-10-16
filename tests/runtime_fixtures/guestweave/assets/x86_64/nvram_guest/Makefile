# Build the self-contained x86_64 IIB demo guest.
#
# -no-pie + -nostdlib + -nostartfiles + -ffreestanding yields an ET_EXEC
# ELF with every symbol at a fixed absolute VA. That lets the intervention
# manifest hard-code absolute addresses resolved with `readelf -s`.

CC ?= x86_64-linux-gnu-gcc
OUT := fmst_x86_nvram_guest
SRC := fmst_x86_nvram_guest.c

CFLAGS := \
  -static \
  -nostdlib \
  -nostartfiles \
  -ffreestanding \
  -fno-builtin \
  -fno-stack-protector \
  -no-pie \
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
