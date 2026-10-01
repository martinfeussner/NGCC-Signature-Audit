# Pristine-source validation

This directory independently checks that the Galas cross-variant attack does
not depend on the repaired wrapper. It builds the untouched submitted reference
implementation for all eight S/F profiles, compares complete serialized signer
transcripts with the specification oracle, recovers the exact normative key
from one same-key, same-message S/F pair at each field size, and sends a fresh
forgery through the untouched submitted F verifier.

The same-key, same-message cross-variant prerequisite is essential. This
experiment does not claim an isolated single-variant EUF-CMA break.

## Included evidence

- `pristine-source/` contains the 552 files from the submission's
  `Implementations/Reference_Implementation` tree. Their contents are pinned by
  `PRISTINE_SOURCE.SHA256SUMS`.
- `pristine_cli.c`, `Makefile`, and `run_validation.sh` are the complete replay
  harness. The Makefile's path to the specification oracle was changed from
  its audit-workspace location to `../..`; the compiled inputs are unchanged.
- `REPORT.md` explains the method and results.
- `recorded-build.log` and `recorded-validation.log` preserve the original audit
  build and execution records.
- `REPAIRED_ORACLE_INPUTS.SHA256SUMS` pins the package sources used for the
  comparison.
- `SOURCE_ARCHIVE.sha256` identifies the authoritative `sign-12.zip` from which
  the pristine tree was extracted.
- `ORIGINAL_VALIDATION_TREE.SHA256SUMS` pins the complete retained audit tree.
  It includes generated binaries and per-run artifacts that are intentionally
  omitted here, so it is an archival identifier rather than an in-package
  `sha256sum -c` target. Package-relative path adaptations are covered by the
  release manifest instead.
- `LICENSE-GALAS.txt` is a copy of the MIT license shipped at
  `Implementations/Optimized_Implementation/Galas-160F/LICENSE` in the Galas
  submission archive.

The package-level `../../SHA256SUMS` is the manifest for all files actually
included in the release.

The unedited audit report refers to these retained logs by their original
workspace names, `build.log` and `out/final/validation.log`. They are named
`recorded-build.log` and `recorded-validation.log` here so a replay cannot
overwrite the evidence shipped in the package.

## Requirements

The replay needs Bash, GNU Make, a C99 compiler, GNU coreutils, and GNU
`/usr/bin/time`. It requires no network access or external cryptographic
library. The four field sizes run concurrently; the recorded run took about
eleven minutes on the audit host.

## Replay

From this directory:

```sh
(cd pristine-source && sha256sum -c ../PRISTINE_SOURCE.SHA256SUMS)
sha256sum -c REPAIRED_ORACLE_INPUTS.SHA256SUMS
make clean
mkdir -p out
make -j16 all 2>&1 | tee out/build.log
./run_validation.sh
```

A successful run ends with these summary lines in
`out/final/validation.log`:

```text
pristine_source_integrity_before=pass files=552
pristine_source_integrity_after=pass files=552
all_profiles_transcript_equivalence=pass profiles=8
all_levels_pristine_verifier_forgery=pass levels=4
```

The script verifies complete transcript equality for all eight profiles. At
160, 256, 384, and 512 bits, recovery receives only the two signatures emitted
by the original S/F interfaces. After recovery, `sign-norm` performs only the
documented conversion from normative `k` to the wrapper's public-`x` cache
format `x || k`, then calls the untouched `sig_sign`; the resulting fresh
signature is accepted by untouched `sig_verify`.
