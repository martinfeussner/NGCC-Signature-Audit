CC ?= gcc
CFLAGS ?= -std=c99 -Wall -Wextra -Wpedantic -O2 -D_POSIX_C_SOURCE=200809L
ORACLE := oracle
G := $(ORACLE)/galas
N := $(ORACLE)/ngcc
BUILD := build

SIG_SRCS := $(G)/gf2n.c $(G)/owf.c $(G)/bf.c $(G)/xof.c \
 $(G)/bavc.c $(G)/vole.c $(G)/instances.c $(G)/universal_hashing.c \
 $(G)/vole_check_ref.c $(G)/qs_proof_ref.c $(G)/quicksilver.c \
 $(G)/qs_gadgets.c $(G)/random_oracle.c $(G)/sign_helpers.c \
 $(G)/challenge.c $(G)/qs_constraint.c $(G)/qs_full_constraints.c \
 $(N)/auxfunc.c $(N)/drng.c $(N)/SIG_SpecOracle.c

COMMON_FLAGS := $(CFLAGS) -I$(G) -I$(N)

all: $(BUILD)/oracle_160s $(BUILD)/oracle_160f \
 $(BUILD)/cross_variant_recover $(BUILD)/file_xor $(BUILD)/coverage_analysis

extended: all $(BUILD)/oracle_256s $(BUILD)/oracle_256f $(BUILD)/cross_variant_recover_256 \
 $(BUILD)/oracle_384s $(BUILD)/oracle_384f $(BUILD)/cross_variant_recover_384 \
 $(BUILD)/oracle_512s $(BUILD)/oracle_512f $(BUILD)/cross_variant_recover_512

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/oracle_160s: oracle_cli.c $(SIG_SRCS) | $(BUILD)
	$(CC) $(COMMON_FLAGS) -DGALAS_INSTANCE=GALAS_160S \
	 -DGALAS_INSTANCE_NAME=\"Galas-160S\" oracle_cli.c $(SIG_SRCS) -o $@

$(BUILD)/oracle_160f: oracle_cli.c $(SIG_SRCS) | $(BUILD)
	$(CC) $(COMMON_FLAGS) -DGALAS_INSTANCE=GALAS_160F \
	 -DGALAS_INSTANCE_NAME=\"Galas-160F\" oracle_cli.c $(SIG_SRCS) -o $@

define ORACLE_template
$(BUILD)/oracle_$(1)s: oracle_cli.c $$(SIG_SRCS) | $(BUILD)
	$$(CC) $$(COMMON_FLAGS) -DGALAS_INSTANCE=GALAS_$(1)S \
	 -DGALAS_INSTANCE_NAME=\"Galas-$(1)S\" oracle_cli.c $$(SIG_SRCS) -o $$@

$(BUILD)/oracle_$(1)f: oracle_cli.c $$(SIG_SRCS) | $(BUILD)
	$$(CC) $$(COMMON_FLAGS) -DGALAS_INSTANCE=GALAS_$(1)F \
	 -DGALAS_INSTANCE_NAME=\"Galas-$(1)F\" oracle_cli.c $$(SIG_SRCS) -o $$@
endef

$(eval $(call ORACLE_template,256))
$(eval $(call ORACLE_template,384))
$(eval $(call ORACLE_template,512))

$(BUILD)/cross_variant_recover: cross_variant_recover.c \
 $(G)/instances.c $(G)/challenge.c $(G)/random_oracle.c $(G)/xof.c \
 $(G)/vole.c $(G)/bavc.c $(N)/auxfunc.c | $(BUILD)
	$(CC) $(COMMON_FLAGS) cross_variant_recover.c $(G)/instances.c \
	 $(G)/challenge.c $(G)/random_oracle.c $(G)/xof.c $(G)/vole.c \
	 $(G)/bavc.c $(N)/auxfunc.c -o $@

$(BUILD)/file_xor: file_xor.c | $(BUILD)
	$(CC) $(CFLAGS) file_xor.c -o $@

$(BUILD)/coverage_analysis: coverage_analysis.c $(G)/instances.c | $(BUILD)
	$(CC) $(COMMON_FLAGS) coverage_analysis.c $(G)/instances.c -o $@

define RECOVER_template
$(BUILD)/cross_variant_recover_$(1): cross_variant_recover.c \
 $(G)/instances.c $(G)/challenge.c $(G)/random_oracle.c $(G)/xof.c \
 $(G)/vole.c $(G)/bavc.c $(N)/auxfunc.c | $(BUILD)
	$$(CC) $$(COMMON_FLAGS) -DPAIR_S_ID=GALAS_$(1)S -DPAIR_F_ID=GALAS_$(1)F \
	 -DPAIR_LABEL=\"$(1)\" cross_variant_recover.c $$(G)/instances.c \
	 $$(G)/challenge.c $$(G)/random_oracle.c $$(G)/xof.c $$(G)/vole.c \
	 $$(G)/bavc.c $$(N)/auxfunc.c -o $$@
endef

$(eval $(call RECOVER_template,256))
$(eval $(call RECOVER_template,384))
$(eval $(call RECOVER_template,512))

clean:
	rm -rf $(BUILD) out

.PHONY: all extended clean
