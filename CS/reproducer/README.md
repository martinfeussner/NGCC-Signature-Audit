# CS-128 posterior-amplification reproducer

This directory reproduces the fixed-key CS-128 attack described in the paper.
It independently implements and strengthens the compressed
signature leakage [reported by Yijian Liu on behalf of Xianhui
Lu](https://ngcc.dev/reports/sign-07.html): a rough
public estimate of the hidden low term is fed back into the verifier-visible
reconstruction, and all 64 hidden block-sign choices are scored for each later
signature.  Regression produces a nearly correct ternary `s1` candidate, the
fixed public ladder completes an equivalent signing key, and the submitted
verifier accepts a signature on a fresh message.

The demonstrated result is for one deterministic, ordinary CS-128 key.  It
does not measure success probability across keys, and it makes no practical
sample-complexity claim for CS-256 or CS-512.

Every transcript used by the reported result came from the submitted
`CS_Sign` path and unmodified `sampling.c`.  The local signing-oracle process
necessarily holds the target secret key, but the estimator consumes only the
public key and ordinary signature fields.  The program compares its output to
the target secret when printing diagnostic error counts; those comparisons do
not enter the posterior score, coefficient rounding, public completion,
equivalent-key construction, or verifier decision.

## Fast evidence replay

The `evidence` directory contains the frozen streaming moment states from the
reported run.  No signature corpus is needed.  With a POSIX shell, GCC,
Python 3, and standard Unix checksum tools installed, run:

```sh
./verify_evidence.sh
```

The script verifies every evidence digest and the submitted source hashes,
checks the optimized 64-way posterior calculation against direct evaluation,
recomputes the stage-one low-term estimate, and replays every 100,000-signature
refinement checkpoint.  It requires rejection through 1.2 million refinement
signatures and an accepted fresh-message forgery at 1.3 million.  It then
repeats the full ladder with every ground-truth array used by the diagnostic
code replaced by unrelated values; the first success, public correction, and
forgery must remain unchanged.  On the test machine this replay takes under a
minute after compilation.

The frozen state files are raw little-endian x86-64 records containing
IEEE-754 `double` values.  Run the full experiment instead when reproducing on
an architecture with a different binary representation.

The bundled `reference/CS-128` tree preserves CRLF copies of the submitted
files.  After line-ending normalization, `cs.c` and `sampling.c` are
byte-identical to the files in the official CS archive; their bundled byte
hashes are checked before every build.  The attack copy
of `ntt.c` is byte-identical to the submitted file; `attack/NTT.h` is only a
case-sensitive-filesystem compatibility shim for the submission's
`NTT.h`/`ntt.h` filename conflict.

An AddressSanitizer and UndefinedBehaviorSanitizer replay reaches the same
public completion and accepted forgery without a memory-access diagnostic.
UndefinedBehaviorSanitizer reports pre-existing shift and signed-overflow
operations in the submitted support code and copied NTT.  For byte-level
reproduction, use the GCC version and flags recorded in `evidence/RUN_METADATA.txt`.

## Full experiment

Run the calibration and the 100,000-signature public refinement ladder:

```sh
./run_full.sh
```

The command creates four independent 250,000-signature calibration streams,
then refinement streams with cumulative states every 100,000 signatures.
Worker IDs 1--4 and 101 onward select distinct DRNG seeds, and every message
contains its worker ID and counter.  The scanner tests checkpoints in fixed
worker order and selects the first one whose public completion yields a
reference-verifier-accepted fresh-message signature.  The reported evidence
first succeeds after 1.3 million refinement signatures, for 2.3 million
signatures including calibration.  The immediately preceding 2.2-million
total checkpoint fails.  During the third stream, the script pauses the signer
after every 100,000 signatures, runs both public tests, and closes the
collector at the first common success.  It therefore stops after 300,000
signatures from that stream in the reported experiment.  Generated files
remain under the ignored `build/` directory.  The paper reports both aggregate
user CPU and observed elapsed time from a four-core Intel Core i5-6500 desktop.

For interactive collection, set `CS_PAUSE_AT_CHECKPOINT=1` when launching a
collector directly.  It writes the cumulative state, prints
`checkpoint_state_ready`, and waits for one input line before collecting the
next 100,000 signatures.  This permits the public merge and verifier test to
run before deciding whether collection should continue.
