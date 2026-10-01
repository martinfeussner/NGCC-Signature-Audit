# Galas cross-variant secret-key recovery reproducer

This package reproduces a specification-level cross-variant key/domain-separation
defect under same-key reuse in Galas. Given a geometrically successful pair of
one S signature and one F signature on the same message under the same
public/secret pair `(pk,k)` at a fixed field size, the attack combines the two
BAVC openings, recovers the exact secret key, and uses it to create a valid
signature on a fresh message. Each attempt uses two signing queries, and its
success is publicly testable; failed geometry is handled by retrying on another
common message. Recovery and fresh-message forgery were reproduced at 160,
256, 384, and 512 bits.

The Galas specification does not instruct users to reuse a key across S and F.
It also neither prohibits such reuse nor cryptographically separates the S/F
key namespaces. The result is conditional on same-key, same-message access to
both variants and is not an isolated single-variant EUF-CMA break.

## Requirements

- a POSIX shell;
- GNU Make;
- a C99 compiler (tested with GCC 13 and Clang at `-O2`); and
- `sha256sum` and `cmp`.

No network access or external cryptographic library is required. A typical run takes about
20 seconds including compilation and stays well below 16 MiB of RAM at Galas-160.

## Portable specification-oracle replay

From this directory:

```sh
./run.sh
```

The final line must be:

```text
minimal_reproducer=pass
```

An optional longer run reproduces exact recovery and a fresh F-variant forgery at the remaining
field sizes:

```sh
./run_all_levels.sh
```

Its final line must be `all_levels_reproducer=pass`. The portable 512-bit signer makes this run
take several minutes; recovery itself takes about one second.

The Galas-160 run performs these checks:

1. generate one normative Galas-160 key pair;
2. sign the same chosen message under Galas-160S and Galas-160F;
3. verify both original signatures;
4. confirm that the F transcript alone cannot recover its hidden tree-0 leaf;
5. combine the S/F openings and recover the exact retained key;
6. sign and verify a fresh message with the recovered key; and
7. reject wrong-message, wrong-key, mutated-signature, and nonmatching-transcript controls.

The original key is passed only to the two signing calls. `cross_variant_recover` receives only
the two public signature byte strings. The later `cmp` is an experiment control that establishes
exact original-key recovery.

`evidence/release-check.log` records a clean run from this release tree. Its recovered and
retained key hashes are both
`01f62f9bd378ef93973c4c172ba0b804377b165244c4eb6d66319ac24e50bb76`, and the fresh-message
forgery hash is `c2ca5bc9d6a3e6e8665b95796119091bc70c163321bdcf2cc35f920237b795da`.
`evidence/clang-release-check.log` records the matching Clang run.

## Untouched submitted-source replay

The stronger validation in `evidence/pristine-validation/` includes all 552
files from the submitted reference-source tree. It establishes complete
submitted-versus-repaired transcript equality for all eight S/F profiles and
runs exact recovery plus a fresh-message forgery through the untouched
submitted interfaces at every field size. From that directory:

```sh
(cd pristine-source && sha256sum -c ../PRISTINE_SOURCE.SHA256SUMS)
sha256sum -c REPAIRED_ORACLE_INPUTS.SHA256SUMS
make clean
mkdir -p out
make -j16 all 2>&1 | tee out/build.log
./run_validation.sh
```

This replay additionally requires Bash and GNU `/usr/bin/time`. It takes
several minutes and runs the four levels concurrently. See
`evidence/pristine-validation/README.md` and
`evidence/pristine-validation/REPORT.md` for the exact checks, recorded hashes,
negative controls, and resource measurements.

## Mathematical mechanism

For fixed `lambda`, S and F use the same key relation and omit the variant identifier from
`Hmsg`, `Hseed`, `Hiv`, and the GGM tree frame. Equal `(pk,sk,message)` values therefore give
equal root seeds, IVs, and seeds at every common heap index. The F opening hides one tree-0
leaf seed. That F leaf index is an internal node of the much larger S tree, and
the S opening permits reconstruction of its node seed with probability close to
one. Once all F tree-0 seeds are known, the public VOLE expansion reconstructs
`u_F`, and the signature field `d_F` gives

```text
w = d_F xor u_F
k = first lambda bits of w.
```

The attack needs the same key and same chosen message in both variants. It does
not claim to break a deployment that cryptographically types and independently
generates every S/F key.

## Specification repairs in the oracle

The submitted wrapper has unrelated implementation defects. `oracle/ngcc/SIG_SpecOracle.c`
implements the PDF algorithms directly: mandatory seeded key generation, normative `sk=k`,
an explicit `(pk,sk,message)` signing interface, and full message lengths. `SPEC_REPAIRS.md`
records these changes. A pristine extraction established byte-identical complete
serialized signatures between the repaired oracle and submitted source for all
eight S/F profiles on matched valid inputs. The recovery program then consumed
only original submitted-interface signatures, and the untouched submitted F
verifier accepted the recovered-key fresh forgery at all four field sizes.

The package also defines the zero-count case of the submitted SM3 rotate macro, which avoids
a C99 undefined shift without changing the fixed-seed outputs. The complete Galas-160 path was
run under AddressSanitizer and UndefinedBehaviorSanitizer; its log is included as
`evidence/postfix-sanitizer.log`.

The authoritative files used during the audit were identified by the following
basenames and hashes. The PDF and original ZIP are not bundled; the exact
552-file reference-source subtree used by the pristine validation is bundled
with its own content manifest.

```text
95d66ea845f96eadd68900db95a0554a6b106dce4c26d972aab33f5eb09c7c19  sign-12-spec.pdf
98d57af868fa10d74b2c0656e565aa14a42ff902646d6fc440ffb7355b75342c  sign-12.zip
```

## Provenance

The attack, derivation, implementation, experiments, and release package were
produced through an AI-run multi-agent audit by OpenAI Codex using Daybreak Blue
at Ultra reasoning effort. A separate hostile-review agent rebuilt and tested
the mechanism. A post-revision hostile review accepted the final manuscript and
pristine-source evidence.
Independent human cryptanalytic review and reproduction remain pending at the
release date.

The accompanying ePrint-style disclosure is included as
[`Galas_Attack_Description.tex`](../Galas_Attack_Description.tex) and
[`Galas_Attack_Description.pdf`](../Galas_Attack_Description.pdf).
The live ngcc.dev checkpoint before the updated disclosure is recorded in
`evidence/prior-art-checkpoint.md`.

## Computational resources

The computations were performed on the Norwegian Research and Education Cloud
(NREC), using resources provided by the University of Bergen and the University
of Oslo.
