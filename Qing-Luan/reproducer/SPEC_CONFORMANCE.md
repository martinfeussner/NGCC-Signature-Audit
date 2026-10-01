# Specification-conformance boundary

The normative experiment follows the submitted Qing Luan PDF. The submitted C
source differs from it in two relevant places:

1. the PDF independently derives each indexed round leaf, while the source
   slices one unindexed XOF stream;
2. the PDF uses one-based round numbers in every `i+c` domain, while the
   source passes zero-based values.

`SPEC_ALIGNMENT.patch` records the complete repair. The directories under
`spec-aligned/` already contain that repair. The attack is tested there first.

Directories under `pristine/` preserve the submitted core semantics. They are
compiled separately only to show that the same extraction also occurs before
the repair. They are not the basis for the specification-level result.

The main PDF abbreviates three key-expansion instance constants. The bundled
protocol reference and submitted source both use `3t+1`, `3t+2`, and
`3t+3`; the aligned copies retain those constants.

The extractor itself receives only a public key, two distinct messages, and
two serialized signatures. DRBG state and secret data are confined to the
producer/control portion of the harness and are never passed into extraction.

`combined_extractor.c` is compiled twice at each level. With
`SPEC_ALIGNED=1`, its round-seed expansion and witness-only signer use the
PDF's independently indexed leaves and one-based domains. With
`SPEC_ALIGNED=0`, they use the untouched submitted core semantics. The two
builds therefore test the same public cross-branch equation without silently
mixing signer or verifier domains.
