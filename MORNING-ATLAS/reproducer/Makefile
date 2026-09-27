CC ?= cc
CFLAGS ?= -O3 -std=gnu11 -Wall -Wextra
REFERENCE := faithful_lwrdsa128
COMMON_NAMES := SIG_lwrdsa128.c packing.c polyvec.c poly.c rounding.c auxfunc.c drng.c
COMMON := $(addprefix $(REFERENCE)/,$(COMMON_NAMES))
INCLUDES := -I$(REFERENCE)

.PHONY: all clean
all: build/morning_faithful_constraints \
     build/morning_faithful_hint_constraints \
     build/morning_public_lwr_export \
     build/morning_equivalent_key_forge \
     build/morning_verify_forgery

build:
	mkdir -p $@

build/morning_faithful_constraints: morning_faithful_constraints.c $(COMMON) | build
	$(CC) $(CFLAGS) $(INCLUDES) $^ -lm -o $@

build/morning_faithful_hint_constraints: morning_faithful_hint_constraints.c $(COMMON) | build
	$(CC) $(CFLAGS) $(INCLUDES) $^ -lm -o $@

build/morning_public_lwr_export: morning_public_lwr_export.c $(COMMON) | build
	$(CC) $(CFLAGS) $(INCLUDES) $^ -lm -o $@

build/morning_equivalent_key_forge: morning_equivalent_key_forge.c $(COMMON) | build
	$(CC) $(CFLAGS) $(INCLUDES) $^ -lm -o $@

build/morning_verify_forgery: morning_verify_forgery.c $(COMMON) | build
	$(CC) $(CFLAGS) $(INCLUDES) $^ -lm -o $@

clean:
	rm -rf build
