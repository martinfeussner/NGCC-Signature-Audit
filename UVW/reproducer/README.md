# UVW-128 pair-leakage reproducer

This directory contains the public attack pipeline from the paper. Ordinary
submitted signatures are converted into complete public error vectors, the
parameter-derived likelihood score identifies high-confidence hidden pairs,
and 1,600 oriented public-column sums define the hidden subspace. Quotienting
by that subspace recovers all 4,850 pairs and relative scales. The final C
program constructs an equivalent decoder and produces a signature on a fresh
message that passes the intended `uvw_verify` predicate.

The attack does not use the submitted API wrapper's separate accept-all bug.
The collector retains a private key only inside its local signing-oracle
process. It writes the public key and errors reconstructed from public
signatures; it does not write a secret key, hidden-pair map, or diagnostic
labels. `uvw_pair_likelihood.py` has no interface for secret labels.

## Fast public-evidence replay

The `evidence` directory contains the public key, 300 reconstructed public
errors, resulting candidate list, and 1,244-byte API signature from the
reported fixed-key experiment. It contains no secret key or truth map. With
Git, a POSIX shell, a C compiler, Python 3, and NumPy installed, run:

```sh
./verify_evidence.sh
```

The script fetches pinned NGCC harness commit
`37ce9750cafd7ea0db0be255e4e8e02f10fe7841`, checks every evidence digest,
recomputes the candidate file, reconstructs the equivalent decoder, verifies
the fresh-message forgery with the intended verifier, requires the same
signature to fail for a changed message, and checks the exact 1,244-byte API
encoding. The statistical and algebraic replay takes about one minute on the
machine reported in the paper, excluding the first source fetch and build.
Set `NGCC_HARNESS` to an existing checkout of the pinned commit to avoid the
clone, and set `PYTHON` if NumPy is installed in a non-default interpreter.

The public-key evidence uses the submission's internal `UVWSPUBK` file
container, which adds an eight-byte header. The forged-signature evidence is
the submitted API byte string and has no `UVWSSIGN` header.

## Full experiment

Regenerate the experiment's deterministic UVW-128 key, collect 300 signatures with four
independently initialized worker DRNG states, run recovery, and forge with:

```sh
./run_full.sh 300 4
```

Key generation took 132.8 seconds and the 300-signature collection took 47.53
minutes on the four-core Intel Core i5-6500 used in the paper. The observed
300-signature success threshold is a one-key result; fresh keys may require a
different number of signatures. The public stopping conditions are the
expected 1,600-dimensional candidate span, a unique quotient partner for all
9,700 columns, and final intended-verifier acceptance.

Generated files are placed under the ignored `build/` directory. Set
`UVW_SEED_COUNT` to override the fixed public candidate count of 1,600 for
diagnostic experiments.
