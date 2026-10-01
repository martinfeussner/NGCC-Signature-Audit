CC ?= gcc
CFLAGS ?= -std=c99 -Wall -Wextra -Wpedantic -O2 -D_POSIX_C_SOURCE=200809L
BUILD := build
SRCROOT := pristine-source/Implementations/Reference_Implementation
REPRO := ../..
ORACLE := $(REPRO)/oracle

PROFILES := 160s 160f 256s 256f 384s 384f 512s 512f
LEVELS := 160 256 384 512

define UPPER
$(shell printf '%s' $(1) | tr '[:lower:]' '[:upper:]')
endef

define PRISTINE_template
P_$(1) := $(SRCROOT)/Galas-$(subst s,S,$(subst f,F,$(1)))
G_$(1) := $$(P_$(1))/galas
N_$(1) := $$(P_$(1))/ngcc
S_$(1) := $$(G_$(1))/gf2n.c $$(G_$(1))/owf.c $$(G_$(1))/bf.c $$(G_$(1))/xof.c \
 $$(G_$(1))/bavc.c $$(G_$(1))/vole.c $$(G_$(1))/instances.c \
 $$(G_$(1))/universal_hashing.c $$(G_$(1))/vole_check_ref.c \
 $$(G_$(1))/qs_proof_ref.c $$(G_$(1))/quicksilver.c $$(G_$(1))/qs_gadgets.c \
 $$(G_$(1))/random_oracle.c $$(G_$(1))/sign_helpers.c $$(G_$(1))/challenge.c \
 $$(G_$(1))/qs_constraint.c $$(G_$(1))/qs_full_constraints.c \
 $$(N_$(1))/auxfunc.c $$(N_$(1))/drng.c $$(N_$(1))/SIG_AlgorithmInstance.c

$$(BUILD)/pristine_$(1): pristine_cli.c $$(S_$(1)) | $$(BUILD)
	$$(CC) $$(CFLAGS) -DGALAS_INSTANCE=GALAS_$(call UPPER,$(1)) \
	 -DGALAS_INSTANCE_NAME=\"Galas-$(subst s,S,$(subst f,F,$(1)))\" \
	 -I$$(G_$(1)) -I$$(N_$(1)) pristine_cli.c $$(S_$(1)) -o $$@
endef

$(foreach p,$(PROFILES),$(eval $(call PRISTINE_template,$(p))))

OG := $(ORACLE)/galas
ON := $(ORACLE)/ngcc
ORACLE_SRCS := $(OG)/gf2n.c $(OG)/owf.c $(OG)/bf.c $(OG)/xof.c \
 $(OG)/bavc.c $(OG)/vole.c $(OG)/instances.c $(OG)/universal_hashing.c \
 $(OG)/vole_check_ref.c $(OG)/qs_proof_ref.c $(OG)/quicksilver.c \
 $(OG)/qs_gadgets.c $(OG)/random_oracle.c $(OG)/sign_helpers.c \
 $(OG)/challenge.c $(OG)/qs_constraint.c $(OG)/qs_full_constraints.c \
 $(ON)/auxfunc.c $(ON)/drng.c $(ON)/SIG_SpecOracle.c

define ORACLE_template
$$(BUILD)/oracle_$(1): $$(REPRO)/oracle_cli.c $$(ORACLE_SRCS) | $$(BUILD)
	$$(CC) $$(CFLAGS) -DGALAS_INSTANCE=GALAS_$(call UPPER,$(1)) \
	 -DGALAS_INSTANCE_NAME=\"Galas-$(subst s,S,$(subst f,F,$(1)))\" \
	 -I$$(OG) -I$$(ON) $$(REPRO)/oracle_cli.c $$(ORACLE_SRCS) -o $$@
endef

$(foreach p,$(PROFILES),$(eval $(call ORACLE_template,$(p))))

define RECOVER_template
$$(BUILD)/recover_$(1): $$(REPRO)/cross_variant_recover.c \
 $$(OG)/instances.c $$(OG)/challenge.c $$(OG)/random_oracle.c $$(OG)/xof.c \
 $$(OG)/vole.c $$(OG)/bavc.c $$(ON)/auxfunc.c | $$(BUILD)
	$$(CC) $$(CFLAGS) -DPAIR_S_ID=GALAS_$(1)S -DPAIR_F_ID=GALAS_$(1)F \
	 -DPAIR_LABEL=\"$(1)\" -I$$(OG) -I$$(ON) \
	 $$(REPRO)/cross_variant_recover.c $$(OG)/instances.c $$(OG)/challenge.c \
	 $$(OG)/random_oracle.c $$(OG)/xof.c $$(OG)/vole.c $$(OG)/bavc.c \
	 $$(ON)/auxfunc.c -o $$@
endef

$(foreach l,$(LEVELS),$(eval $(call RECOVER_template,$(l))))

$(BUILD):
	mkdir -p $(BUILD)

all: $(foreach p,$(PROFILES),$(BUILD)/pristine_$(p) $(BUILD)/oracle_$(p)) \
 $(foreach l,$(LEVELS),$(BUILD)/recover_$(l))

clean:
	rm -rf $(BUILD) out

.PHONY: all clean
