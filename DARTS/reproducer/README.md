# DARTS-128 ternary-secret recovery reproducer

This directory contains the complete public attack pipeline used in the
paper: streaming collection, public normal-equation scores, deterministic
classifier and support ladders, binary-choice lattice completion, public-key
validation, equivalent-key construction, and a fresh-message forgery.

The demonstrated result is one fixed DARTS-128 key. The 17-million-signature
collection took about 13.14 hours on the reported four-core Intel i5-6500. The
completion grid was designed retrospectively on that target, so this evidence
does not measure success probability over random keys. Recovery returns the
exact ternary `(s0,s1,e)` values and constructs an equivalent signing key with
a fresh seed; it does not recover the original seed.

## Fast public-evidence replay

The `evidence/` directory contains the 9,336-byte public score, public matrix,
final reduced public basis, recovered ternary secret, and accepted signature.
No signing key, branch labels, or target-secret labels are included. Install
NumPy and `fpylll` 0.6.4, then run:

```sh
PYTHON=/path/to/python-with-fpylll ./verify_evidence.sh
```

The replay reconstructs the secret from the public score and reduced basis,
checks it byte-for-byte against the published result, creates the equivalent
key, reproduces the accepted signature, and requires a changed-message control
to reject.

## Full collection

Requirements are Git, GNU Make, a C compiler with OpenMP, and Python 3 with
NumPy and fpylll. The build script fetches pinned NGCC harness commit
`37ce9750cafd7ea0db0be255e4e8e02f10fe7841` for the submitted DARTS source.
Run the complete collection, public completion, equivalent-key construction,
and fresh-message forgery using four workers with:

```sh
PYTHON=/path/to/python-with-fpylll ./run_full.sh 17000000 0 4
```

The collector is resumable through
`build/full-key-0/collection/state.bin`. Its attack state contains the public
key and streaming public statistics. The generated score and public matrix are
written beside it. To run collection separately, use `collect.sh` with the
same first three arguments and an optional output directory.

## From-scratch lattice completion

Install [flatter](https://github.com/keeganryan/flatter) and run:

```sh
PYTHON=/path/to/python-with-fpylll ./complete_from_score.sh \
  build/collection/scores.bin build/collection/public-matrix.txt
```

This fixes public classifier-width rung 2 and support rung 2, builds the raw
178-dimensional basis, applies Flatter at RHF 1.01, then two BKZ-20 and two
BKZ-30 loops with 256-bit MPFR arithmetic. On the saved evidence, the measured
reduction time was about five minutes with peak RSS below 90 MiB.

Set `NGCC_HARNESS` to a checkout of the pinned harness commit to avoid its
clone. Set `PYTHON` to the interpreter containing NumPy and fpylll.
