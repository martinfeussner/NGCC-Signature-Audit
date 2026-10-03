CC ?= cc
CFLAGS ?= -O3 -march=native -std=gnu11 -Wall -Wextra -Wpedantic
CPPFLAGS_COMMON := -DUSE_SHA3 -I src/native

NATIVE := src/native
PDF_FULL := src/pdf_full_entropy
COMMON := \
	$(NATIVE)/bitstream.c \
	$(NATIVE)/canonical.c \
	$(NATIVE)/corank1.c \
	$(NATIVE)/field.c \
	$(NATIVE)/fips202.c \
	$(NATIVE)/hashkdf.c \
	$(NATIVE)/matrixelim.c \
	$(NATIVE)/matrixmod.c \
	$(NATIVE)/osfreq.c \
	$(NATIVE)/randombytes.c \
	$(NATIVE)/triform.c \
	$(NATIVE)/trine.c \
	$(NATIVE)/trine_codec.c \
	$(NATIVE)/trine_expand.c \
	$(NATIVE)/util.c

PDF_FULL_COMMON := \
	$(PDF_FULL)/bitstream.c \
	$(PDF_FULL)/canonical.c \
	$(PDF_FULL)/corank1.c \
	$(PDF_FULL)/field.c \
	$(PDF_FULL)/fips202.c \
	$(PDF_FULL)/hashkdf.c \
	$(PDF_FULL)/matrixelim.c \
	$(PDF_FULL)/matrixmod.c \
	$(PDF_FULL)/osfreq.c \
	$(PDF_FULL)/randombytes.c \
	$(PDF_FULL)/triform.c \
	$(PDF_FULL)/trine.c \
	$(PDF_FULL)/trine_codec.c \
	$(PDF_FULL)/trine_expand.c \
	$(PDF_FULL)/util.c

PORTABLE_COMMON := \
	$(NATIVE)/canonical.c \
	$(NATIVE)/corank1.c \
	$(NATIVE)/field.c \
	$(NATIVE)/matrixelim.c \
	$(NATIVE)/matrixmod.c \
	$(NATIVE)/triform.c \
	$(NATIVE)/trine_expand.c \
	$(NATIVE)/trine_codec.c \
	$(NATIVE)/bitstream.c \
	$(NATIVE)/hashkdf.c \
	$(NATIVE)/fips202.c \
	$(NATIVE)/util.c

.PHONY: all clean
all: bin/hostile_balanced bin/hostile_shortsig \
	bin/bench_seed_balanced bin/bench_seed_shortsig \
	bin/portable_balanced bin/portable_shortsig bin/partial_invariant \
	bin/full_entropy_balanced bin/full_entropy_shortsig

bin/hostile_balanced: $(NATIVE)/hostile_attack.c $(COMMON) | bin
	$(CC) $(CFLAGS) $(CPPFLAGS_COMMON) -DHOSTILE_PDF_UNSALTED \
		-DHOSTILE_REDUCED_SEED_BITS=6 -DPARAMS=1 $^ -lssl -lcrypto -o $@

bin/hostile_shortsig: $(NATIVE)/hostile_attack.c $(COMMON) | bin
	$(CC) $(CFLAGS) $(CPPFLAGS_COMMON) -DHOSTILE_PDF_UNSALTED \
		-DHOSTILE_REDUCED_SEED_BITS=6 -DPARAMS=4 $^ -lssl -lcrypto -o $@

bin/bench_seed_balanced: $(NATIVE)/bench_seed_decode.c $(COMMON) | bin
	$(CC) $(CFLAGS) $(CPPFLAGS_COMMON) -DHOSTILE_PDF_UNSALTED \
		-DHOSTILE_REDUCED_SEED_BITS=6 -DPARAMS=1 $^ -lssl -lcrypto -o $@

bin/bench_seed_shortsig: $(NATIVE)/bench_seed_decode.c $(COMMON) | bin
	$(CC) $(CFLAGS) $(CPPFLAGS_COMMON) -DHOSTILE_PDF_UNSALTED \
		-DHOSTILE_REDUCED_SEED_BITS=6 -DPARAMS=4 $^ -lssl -lcrypto -o $@

bin/portable_balanced: src/portable/natural_collision_toy.c $(PORTABLE_COMMON) | bin
	$(CC) $(CFLAGS) $(CPPFLAGS_COMMON) -DPARAMS=1 $^ -o $@

bin/portable_shortsig: src/portable/shortsig_graph_toy.c $(PORTABLE_COMMON) | bin
	$(CC) $(CFLAGS) $(CPPFLAGS_COMMON) -DPARAMS=4 $^ -o $@

bin/partial_invariant: src/portable/partial_invariant_bench.c $(PORTABLE_COMMON) | bin
	$(CC) $(CFLAGS) $(CPPFLAGS_COMMON) -DPARAMS=1 $^ -lm -o $@

bin/full_entropy_balanced: $(PDF_FULL)/one_shot.c $(PDF_FULL_COMMON) | bin
	$(CC) $(CFLAGS) -DUSE_SHA3 -DPARAMS=1 -I $(PDF_FULL) \
		$^ -lssl -lcrypto -o $@

bin/full_entropy_shortsig: $(PDF_FULL)/one_shot.c $(PDF_FULL_COMMON) | bin
	$(CC) $(CFLAGS) -DUSE_SHA3 -DPARAMS=4 -I $(PDF_FULL) \
		$^ -lssl -lcrypto -o $@

bin:
	mkdir -p bin

clean:
	rm -rf bin results/latest/*
