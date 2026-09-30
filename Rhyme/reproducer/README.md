# Rhyme-128 order-dependent rejection-sampling reproducer

This directory reproduces the attack in **Order-Dependent Rejection Sampling
in Rhyme-128: Exact Secret-Tail Recovery and a Fresh-Message Forgery Using at
Most 40,000 Signatures**.

Appendix A of the submitted specification states the correct cumulative
envelope condition, but then replaces its maximum with a boundary term that is
too small. Algorithm 3 leaves the fixed enumeration order unspecified. With a
deterministic central-minus order and the prescribed boundary values, the
sampled offset is usually close to the negative public challenge. Negacyclic
least squares then recovers all 1,024 coefficients of the four-polynomial
secret tail. The recovered public-key relation permits a zero-commitment
fresh-message forgery accepted by the pristine submitted verifier.

This is an attack on the tested deterministic completion of the submitted
specification. The unmodified submitted SHAKE source uses ascending arrays and
`M=1.002214572...`, which satisfies the envelope for its operational CDT
distribution and is outside this attack claim.

## Fast public-evidence replay

Requirements are a POSIX shell, `patch`, GCC or Clang, Python 3, and standard
Unix checksum tools. Run:

```sh
./verify_evidence.sh
```

This command:

1. verifies every bundled reference-source and evidence hash;
2. recomputes the cumulative envelope under both the operational source and
   literal PDF Gaussian conventions;
3. builds a verifier solely from the normalized submitted source;
4. checks the public relation for the frozen recovered tail;
5. regenerates the fresh-message signature and requires pristine acceptance;
6. requires wrong-message, perturbed-tail, and wrong-key controls to reject;
7. compares the regenerated signature with the frozen public evidence.

No signing key or transcript is included in `evidence/`.

## Full attack

Python with NumPy is additionally required. It can be installed with
`python3 -m pip install -r requirements.txt`. To reproduce the manuscript's
independent-rejection-randomness run, execute:

```sh
./run_full.sh independent
```

The script generates the fixed reproducibility key, obtains 50,000 ordinary
chosen-message signatures, and passes every emitted signature through the
pristine submitted verifier and decoder. It removes the scoring secret from
the attack path, recovers from the first 30,000 public records, checks the
public relation, constructs a fresh-message signature with the pristine
codec, and runs all three negative controls. The retained suffix is used only
for residual diagnostics.

To reproduce the Algorithm 6 random-tape-reuse run, use:

```sh
./run_full.sh reuse
```

That run recovers at the public 40,000-signature checkpoint. On the reported
four-core Intel Core i5-6500 desktop, the two 50,000-signature collections took
160.44 and 178.30 seconds. The corresponding 40,000-signature batch
regressions took 6.97 and 9.87 seconds and used about 2.52 GiB of RAM. Generated
oracles and records are written under the ignored `build/` directory.

Set `PYTHON=/path/to/python` or `CC=/path/to/compiler` when needed. An explicit
second argument selects another output directory:

```sh
./run_full.sh independent /path/to/output
```

## Same-key controls

Run:

```sh
./run_controls.sh
```

The first control uses the exact independent-run key, messages, central order,
randomness setup, submitted entropy tables, and signing logic, changing only
`M` to the operationally safe source value. At 40,000 signatures its rounded
candidate is all zero, only 399 of 1,024 coefficients coincide with the target
secret, the public relation fails, and no forgery is accepted. This paired
ablation is evidence consistent with correcting `M` removing the exploited
first-moment channel; it is not a general security proof.

The second same-key diagnostic extends the first-response entropy table so no
otherwise accepted response is restarted for being unencodable. It still
recovers all 1,024 coefficients at 30,000 signatures and constructs a
pristine-verifier-accepted forgery. Its oracle signatures are not presented as
pristine-decodable attack evidence; the diagnostic isolates only the restart
gate.

The submitted-table attack runs recorded 5,696 and 5,578 encoder-only restarts
while producing 50,000 signatures, respectively 10.23% and 10.04% of
pack-stage candidates. No other packing failure occurred.

## Gaussian conventions

`check_envelope.py` exhaustively evaluates every eligible integer mask for
both readings:

| Convention | Challenge parity | Appendix boundary value | Required maximum | Maximizing masks |
|---|---:|---:|---:|---:|
| Operational CDT/source | 0 | `9.3573397e-6` | `1.0019364869` | `±378` |
| Operational CDT/source | 1 | `1.4950374e-6` | `1.0019292771` | `±377` |
| Literal PDF | 0 | `0.0075371423` | `1.1818109123` | `±380` |
| Literal PDF | 1 | `0.0035191981` | `1.1821799192` | `±379` |

The submitted source value is safe for the operational CDT distribution. It
is not an envelope under the literal PDF Gaussian reading. The end-to-end
attack experiments use the operational distributions.

## Contents

- `reference/Rhyme-SHAKE-128/`: the 49 submitted source files, with line
  endings normalized to LF.
- `patches/`: small, reviewable diffs producing each attack or control
  variant.
- `review_collect_oracle_count.c`: signing-oracle collector with encoder
  restart counters.
- `pristine_validate_oracle.c`: pristine verifier/decoder and public-record
  extractor.
- `recover.py`: public-transcript negacyclic FFT regression.
- `review_forge.c`: public-relation check, zero-commitment forger, and negative
  controls.
- `check_envelope.py`: independent standard-library envelope calculation.
- `evidence/`: public key, recovered tail, accepted forgery, result record, and
  checksums.
- `reports/SOURCE_PROVENANCE.md`: source hashes and exact controlled-variant
  definitions.

The bundled candidate source remains subject to its original terms. The
attack code and report are supplied for review and reproduction; independent
human cryptographic verification remains pending.
