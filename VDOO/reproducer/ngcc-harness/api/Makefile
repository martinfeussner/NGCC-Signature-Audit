# Builds the master KAT harness into ../bin/ngcc_kat
NGCC_ROOT ?= ..
CC ?= gcc
CFLAGS ?= -O2 -std=gnu11 -Wall -Wextra -Wno-unused-parameter -D_GNU_SOURCE

.PHONY: harness clean all
all: harness
harness: $(NGCC_ROOT)/bin/ngcc_kat

$(NGCC_ROOT)/bin/ngcc_kat: ngcc_kat.c drng.c drng.h link_common.h link_kem.h link_sig.h link_kex.h link_hash.h
	mkdir -p $(NGCC_ROOT)/bin
	$(CC) $(CFLAGS) -I. -o $@ ngcc_kat.c drng.c -ldl

clean:
	rm -f $(NGCC_ROOT)/bin/ngcc_kat
