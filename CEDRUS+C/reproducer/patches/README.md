# Scheme-favourable source-repair materials

These files document the repaired CEDRUSC-160s reference-source model cited
by the manuscript and `evidence/SOURCE_CONFORMANCE.md`:

- `spec-repair.patch` is the unified diff from the pristine submitted 160s
  reference source to the repaired source;
- `verify_core.c` and `verify_core.h` are the added strict repaired-verifier
  core, including the full-address parsing and WOTS+C membership checks; and
- `spec-repair-hashes.json` pins every submitted and repaired file modified by
  the diff.

The paths inside the unified diff are relative labels for the pristine
submission (`submitted/`) and repaired tree (`spec-repaired/`). The complete
submitted source package is not duplicated here; the minimal untouched 160f
and 160s FORS sources used by the packaged native splice tests are under
`../vendor/`.

These files are supporting evidence and are not silently applied by
`../run_all.sh`. The replay runs the scaled strict repaired-verifier model and
compiles the native FORS splice tests against the bundled untouched source.
The concrete parameter analysis in this release is limited to CEDRUS+C-160f
and CEDRUS+C-160s.

Frozen SHA-256 values:

```text
4a4fd267abd341149abae1662c24a09018f0159cd168209556652d24839e6f41  spec-repair.patch
847741671f63c78cd242623dc9cdd35d878bf521271d35313589a4d08c7f155b  spec-repair-hashes.json
86d3048ade9c722c1a75d12f1e52416aa077fd8c24e07554567e3490ad902456  verify_core.c
73a0a6420c32dd6e3c6ce91dcf48b5d30564b0ce5dc73553374ee224bf9a3163  verify_core.h
```
