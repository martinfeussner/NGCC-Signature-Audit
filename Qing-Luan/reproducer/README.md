# Qing Luan complete pre-signature DRBG state-rollback reproducer

This package reproduces the conditional Qing Luan complete pre-signature DRBG
state-rollback attack described in `../Qing_Luan_Attack_Description.pdf`.

Two distinct messages are signed under one key after complete pre-signature
DRBG state rollback to the same state immediately before both signing calls.
This repeats both the hidden root and public salt; repetition of either value
alone is insufficient. The serialized signatures repeat the hidden per-round
masks but normally receive different
Fiat--Shamir challenges. A combined public-input extractor first uses one
complementary opening: a type-1 seed from one signature reconstructs
`eta_prime`, while the type-0 response in the other publishes
`v = eta - eta_prime`. It therefore recovers `eta` directly. If both second
challenges are identical, the extractor falls back to subtracting two type-0
affine responses. A witness-only signer then creates a signature on an
unqueried message.

The result contradicts Qing Luan's explicit robustness statements for
essentially this complete pre-signature DRBG state-rollback condition. It does
not establish an ordinary fresh-randomness EUF-CMA break. If those robustness
statements are withdrawn, the mechanism should instead be classified as a
conditional fault/caller-misuse attack.

## Requirements

- a C11 compiler (tested with GCC);
- Python 3;
- a POSIX shell.

No network access or external library is required.

## Run

```sh
./run.sh
```

The command builds and tests all four parameter levels against:

1. source aligned with the PDF's independent indexed-leaf and one-based round
   domains;
2. a standalone implementation of the documented DRBG;
3. untouched submitted core semantics as corroboration.

Every trial verifies the two source signatures, extracts from public inputs,
checks the recovered witness against the public relation, forges an unqueried
message, invokes the ordinary verifier, and runs same-message, fresh-state,
corruption, wrong-key, and wrong-message controls. It also prints the exact
ideal fixed-weight probability and a hash-aware layered model. These are model
calculations, not exact probabilities for conditioned serialized signatures.

Expected final lines include `PASS` for every level/backend and a
`QingLuan-512` XOF state-reconstruction check. The final clean replay, including
the sanitizer builds, took 2 minutes 20.24 seconds and peaked at 45,568 KiB RSS
on the NREC audit host.

## Main files

- `hostile_review.c`: independent public extractor, witness-only signer,
  tests, and controls for the affine route;
- `combined_extractor.c`: public cross-branch extractor with affine fallback,
  all controls, and a fresh-message forgery;
- `witness_signer.inc`: witness-only signer parameterized for PDF-aligned and
  untouched source semantics;
- `SPEC_ALIGNMENT.patch`: exact source-to-PDF semantic repair;
- `spec-aligned/`: repaired experiment copies;
- `pristine/`: untouched submitted core copies used only for corroboration;
- `success_probability.py`: exact affine-only ideal-model calculation;
- `rollback_probability.py`: fixed-weight and hash-aware combined-extractor
  model;
- `EVIDENCE.json`: machine-readable hostile-review results;
- `HOSTILE_REVIEW.md`: sealed independent falsification review of the final
  release;
- `HOSTILE_REVIEW_EVIDENCE.json`: machine-readable evidence from that review;
- `SPEC_CLAIM_AUDIT.md`: exact threat and claim boundary;
- `PRIOR_ART.md`: best-effort novelty and related-work review.
- `REFERENCE_VALIDATION.log`: output of the release copy's clean full replay.

Run `./clean.sh` to remove generated executables and logs.
