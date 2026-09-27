HARNESS ?= ../../ngcc-harness
LEVEL ?= 1

SIGN := $(abspath $(HARNESS))/sign-27
NAME := SQIsignTriangle_lvl$(LEVEL)
TREE := $(SIGN)/src/$(NAME)/sqisigntriangle
BUILD := $(SIGN)/build/$(NAME)
LIB := $(SIGN)/lib/lib$(NAME).so
LOCAL_BUILD := build
HELPER := $(LOCAL_BUILD)/recover_codomain_lvl$(LEVEL)

CPPFLAGS := -D_GNU_SOURCE -DSQISIGN_BUILD_TYPE_REF -DSQISIGN_GF_IMPL_REF \
  -DENABLE_SIGN -DTARGET_AMD64 -DRADIX_64 -DHAVE_UINT128 -DTARGET_OS_UNIX \
  -DSQISIGN_TEST_REPS=10 -DSQISIGN_VARIANT=lvl$(LEVEL) \
  -I$(TREE)/include -I$(TREE)/src/nistapi/lvl$(LEVEL) \
  -I$(TREE)/src/common/generic/include -I$(TREE)/src/common/generic \
  -I$(TREE)/src/quaternion/ref/generic/include \
  -I$(TREE)/src/quaternion/ref/generic/internal_quaternion_headers \
  -I$(TREE)/src/quaternion/ref/generic -I$(TREE)/src/mp/ref/generic/include \
  -I$(TREE)/src/gf/ref/include -I$(TREE)/src/precomp/ref/lvl$(LEVEL)/include \
  -I$(TREE)/src/ec/ref/include -I$(TREE)/src/hd/ref/include \
  -I$(TREE)/src/hd/ref/lvlx -I$(TREE)/src/id2iso/ref/include \
  -I$(TREE)/src/verification/ref/include -I$(TREE)/src/signature/ref/include

CFLAGS := -O2 -std=gnu11
LDLIBS := -lgmp -lm

.PHONY: all clean
all: $(HELPER)

$(LIB):
	$(MAKE) -C $(SIGN) lib/lib$(NAME).so

$(LOCAL_BUILD):
	mkdir -p $@

$(HELPER): recover_codomain.c $(LIB) | $(LOCAL_BUILD)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< $(BUILD)/*.o $(LDLIBS) -o $@

clean:
	$(RM) -r $(LOCAL_BUILD)
