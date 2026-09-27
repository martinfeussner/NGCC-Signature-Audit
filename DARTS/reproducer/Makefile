CC ?= cc
CFLAGS ?= -O3 -std=gnu11 -Wall -Wextra
DARTS_DIR ?=

ifeq ($(strip $(DARTS_DIR)),)
$(error Set DARTS_DIR to the submitted DARTS128 reference-source directory)
endif

COMMON_NAMES := sign.c packing.c polyvec.c poly.c ntt.c reduce.c sampler.c \
  encoding.c polyfix.c polymat.c fft.c fixpoint.c symmetric.c drng.c auxfunc.c \
  SIG_AlgorithmInstance.c
COMMON := $(addprefix $(DARTS_DIR)/,$(COMMON_NAMES))
INCLUDES := -I. -I$(DARTS_DIR)

.PHONY: all clean
all: build/darts_collect build/darts_dump_public_matrix build/darts_forge_from_secret

build:
	mkdir -p $@

build/darts_collect: darts_collect.c darts_prepared_sign.c darts_prepared_sign.h darts_scores.h $(COMMON) | build
	$(CC) $(CFLAGS) -fopenmp $(INCLUDES) darts_collect.c darts_prepared_sign.c $(COMMON) -lm -o $@

build/darts_dump_public_matrix: darts_dump_public_matrix.c darts_scores.h $(COMMON) | build
	$(CC) $(CFLAGS) $(INCLUDES) darts_dump_public_matrix.c $(COMMON) -lm -o $@

build/darts_forge_from_secret: darts_forge_from_secret.c darts_scores.h $(COMMON) | build
	$(CC) $(CFLAGS) $(INCLUDES) darts_forge_from_secret.c $(COMMON) -lm -o $@

clean:
	rm -rf build
