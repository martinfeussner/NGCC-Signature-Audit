CC ?= cc
CFLAGS ?= -O2 -fPIC -Wall -Wextra

VDOO128 := ../ngcc-harness/sign-33/Implementation/Reference_Implementation/vdoo_128

.PHONY: all clean

all: libvdoo_hash_helper.so

libvdoo_hash_helper.so: vdoo_hash_helper.c $(VDOO128)/auxfunc.c $(VDOO128)/auxfunc.h
	$(CC) $(CFLAGS) -shared -I$(VDOO128) \
		vdoo_hash_helper.c $(VDOO128)/auxfunc.c -o $@

clean:
	rm -f libvdoo_hash_helper.so
