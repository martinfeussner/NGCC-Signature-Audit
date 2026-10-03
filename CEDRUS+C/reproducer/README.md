# CEDRUS+C ordinary FORS+C accumulation reproducer

This package reproduces a fresh-message forgery mechanism under a strict,
scheme-favourable interpretation of the specification for the two CEDRUS+C
category-I parameter sets, CEDRUS+C-160f and CEDRUS+C-160s. The concrete
parameter analysis is limited to these two sets. The adversary accumulates
ordinary independently randomized signatures at their complete bottom
addresses, mixes covered FORS+C coordinates at one address, and enumerates the
public `R` and counter inputs accepted by the verifier for a never-signed
message.

The attack does not use reset, repeated randomness, deterministic signing,
faults, related or weak keys, the submitted source's tree-index collapse, or
the written verifier's omitted WOTS+C membership check. The strict repaired
verifier uses the full specification address and enforces the strongest
coherent WOTS+C checks.

## Scope and physical qualification

The full-parameter attack was not executed. The analytic attack points have a
constant rigorous success lower bound and fewer than `2^80` signing queries and
attacker public-`HMSG` calls, but their physical resources are enormous. The
soft-`2^80`-byte rows are:

```text
set   sign queries   target HMSG   attacker HMSG Q+T   returned bits   signer cycles
160f  2^71.220       2^66.934      2^71.292            2^88.494        2^100.156
160s  2^75.587       2^71.982      2^75.701            2^91.795        2^108.597
```

Here `Q+T` counts one public `HMSG` evaluation to parse every acquired
signature and the fixed target-search budget. These quantities have different
units and are not combined into a misleading single physical cost.

A fully provisioned table first fits within the frozen NREC audit-host capacity
of 135,045,894,144 bytes at prefix `b=49` for 160f and `b=54` for 160s. Those
rows need `2^73.652` and `2^79.811` attacker `HMSG` calls, while honest signing
alone is estimated at about 1.74 trillion and 1.29 quadrillion years under
ideal 64-core, 2 GHz scaling. They are resource-accounting points, not claims
of practical execution.

## What the replay runs

`./run_all.sh` performs all feasible checks:

1. verifies the immutable checksum manifest;
2. recomputes exact Poisson coverage moments, concentration bounds, optimized
   resource rows, exact `Q=2^64` checks, and storage estimates;
3. independently recomputes the four headline rows by direct Poisson
   recurrence without importing the main analyzer;
4. checks the occupancy moment formula exhaustively and by deterministic Monte
   Carlo;
5. runs the scaled end-to-end strict repaired-verifier forgery and seven
   negative controls;
6. compiles a common harness against the bundled untouched submitted 160f and
   160s FORS cores and runs both full-parameter coordinate-splice tests;
7. runs a second high-precision hostile cross-check, including the
   machine-RAM profiles, exact WOTS+C probabilities, and compact-forest
   formula; and
8. compares every generated JSON file byte-for-byte with the frozen expected
   output and validates the security/scope invariants.

A successful replay ends with:

```text
validation=PASS
```

Generated files are confined to `build/`, `work/`, and `results/latest/`.
They are deleted and recreated by every full replay.

## Requirements

- POSIX shell and standard Unix utilities;
- Python 3.11 or later;
- a C99 compiler (`cc`, GCC, or Clang); and
- `sha256sum`.

No network access and no third-party Python package are required.

## Reproduce

```sh
./run_all.sh
```

To validate the frozen evidence and immutable files without rerunning the
experiments:

```sh
./run_all.sh --validate-only
```

To regenerate the normalized release archive after the manuscript PDF has
been built:

```sh
python3 scripts/make_release_zip.py
```

The ZIP builder sorts entries, normalizes timestamps and permissions, excludes
all disposable output, and then writes
`../CEDRUS+C_FORS_Accumulation_Reproducer.zip`.

## Main files

- `scripts/resource_model.py`: exact main probability and resource analysis;
- `scripts/independent_bounds.py`: independent direct-Poisson headline check;
- `scripts/moment_check.py`: exhaustive and Monte Carlo occupancy tests;
- `scripts/toy_strict_forge.py`: scaled strict repaired-verifier forgery and
  controls;
- `scripts/hostile_crosscheck.py`: independent high-precision reconstruction,
  table audit, exact WOTS+C calculation, and host-RAM profiles;
- `native_fors_splice.c`: common native full-parameter FORS splice harness;
- `patches/`: the source-repair diff, strict repaired-verifier core, and
  hashes needed to inspect the scheme-favourable verification model;
- `vendor/submitted-160f/` and `vendor/submitted-160s/`: minimal untouched
  submitted reference source needed by the native tests;
- `scripts/validate_release.py`: fail-closed release validation;
- `expected/`: frozen byte-for-byte outputs;
- `evidence/`: hostile review, attack ledger, specification-conformance trace,
  lifetime search result, prior-art checkpoint, and performance provenance;
- `SHA256SUMS`: immutable input manifest; and
- `run_all.sh`: single replay entry point.

The bundled submitted source retains its original terms. This package grants
no broader license.

## Prior art and claimed contribution

CEDRUS+C Section 3.2 already gives the generic same-instance FORS+C
accumulation term. Mehdi Abri and Jonathan Katz, *Shorter Hash-Based Signatures
Using Forced Pruning*, IACR ePrint 2025/2069, already account for the public
hash-query multiplier:

<https://eprint.iacr.org/2025/2069>

Mikhail Kudinov, Andreas Hülsing, Eyal Ronen, and Eylon Yogev introduced the
related SPHINCS+C design and its counter-selected FORS+C setting in IACR ePrint
2022/778:

<https://eprint.iacr.org/2022/778>

The claimed contribution is limited to the CEDRUS+C parameter/lifetime
consequence, exact all-address concentration and prefix sharding, concrete
`q_S/q_H` optimization, splice accepted by the strict repaired verifier, and
complete resource accounting. A best-effort check on 3 October 2026 found only
the separate submitted-code tree-index-collapse report on the public CEDRUS+C page:

<https://ngcc.dev/reports/sign-03.html>

## Provenance and review status

The candidate-specific attack instantiation, derivation, implementations,
experiments, resource analysis, manuscript, and release package were produced
by OpenAI Codex using Daybreak Blue at Ultra reasoning effort during an AI-run
audit of NGCC signature candidates. Separately instructed hostile-review
agents reconstructed the strict repaired-verifier model, recomputed the bounds,
rebuilt the native tests, and tried to disprove the result. No human cryptanalyst has
independently reviewed or reproduced it at the release date.

## Computational resources

The computations were performed on the Norwegian Research and Education Cloud
(NREC), using resources provided by the University of Bergen and the University
of Oslo.

The companion manuscript is
[`CEDRUS+C_Attack_Description.tex`](../CEDRUS+C_Attack_Description.tex) and
[`CEDRUS+C_Attack_Description.pdf`](../CEDRUS+C_Attack_Description.pdf).
