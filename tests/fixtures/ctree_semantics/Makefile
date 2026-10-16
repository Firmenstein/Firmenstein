CC ?= gcc
OUT_DIR ?= /tmp/firmenstein-ctree-semantics
CFLAGS := -g -fno-omit-frame-pointer -fno-optimize-sibling-calls

.PHONY: all clean

all: $(OUT_DIR)/ctree_semantics_O0 $(OUT_DIR)/ctree_semantics_O2

$(OUT_DIR):
	mkdir -p $@

$(OUT_DIR)/ctree_semantics_O0: ctree_semantics.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -O0 -o $@ $<

$(OUT_DIR)/ctree_semantics_O2: ctree_semantics.c | $(OUT_DIR)
	$(CC) $(CFLAGS) -O2 -o $@ $<

clean:
	rm -f $(OUT_DIR)/ctree_semantics_O0 $(OUT_DIR)/ctree_semantics_O2
