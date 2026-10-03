# CEDRUS-alpha FORC accumulation and public-HMSG-grinding reproducer

This package reproduces the exact probability calculation, reduced
fresh-message forgery, hostile controls, and repaired-native conformance checks
for a CEDRUS-alpha parameter/lifetime attack.

The attacker collects ordinary independently randomized signatures, groups
them by the complete `h`-bit bottom FORC address, and retains the earliest
revealed chain node for each address, coordinate, and leaf. For a fresh message,
the attacker enumerates public serialized `R` values until `HMSG` selects a
covered coordinate in every FORC tree at one retained address. Each selected
node is hashed only forward and keeps its own authentication path. Because the
FORC public key is fixed by the key and complete address, the coordinates may
come from different signatures and one retained hypertree suffix authenticates
the mixed result.

The verifier determines validity: it reads serialized `R`, recomputes
`HMSG(R, PK.seed, PK.root, M)`, and has no secret input with which to test that
`R` came from `PRF_msg`. Enumerating public `R` values is therefore part of the
ordinary forgery algorithm.

This is an ordinary-signing fresh-message forgery in the specification's
ideal-hash model. It needs no reset, repeated randomness, deterministic mode,
fault, related key, weak key, or submitted implementation defect. It is a
parameter/lifetime result rather than a machine-practical attack. A full-size
forgery was not run.

## Requirements

- Python 3.10 or later, using only the standard library;
- a POSIX shell;
- a C99 compiler (tested with GCC 13.3.0); and
- `sha256sum`, `cmp`, and POSIX `patch`.

No network access or external cryptographic library is required. A clean run
takes about two minutes and less than 40 MiB RSS on the NREC audit host.

## Run

From this directory:

```sh
./run_all.sh
```

The last line must be:

```text
cedrus_alpha_forc_accumulation_reproducer=PASS
```

`run_all.sh` first verifies `IMMUTABLE.SHA256SUMS`. It then regenerates the exact
all-parameter complexity JSON, executes both reduced attacks and the
full-parameter FORC splice test, compiles and runs the repaired 256f native
check, compares every output byte-for-byte with the bundled expected results,
and checks the verdict-critical invariants. All
generated material is confined to `work/` and `build/`, so rerunning does not
change any manifested file. Use `./clean.sh` to remove those directories.
The earlier `./run.sh` command remains as a compatibility wrapper and invokes
the same entry point.

## Expected result

Every submitted parameter set has a Poissonized all-address strategy with a
signing-query mean below `2^80`, attacker public-`HMSG` work `Q+T` below
`2^80`, and success greater than `0.632`. The attacker recomputes `HMSG` once
for each of the `Q` acquired signatures to learn its address, then makes `T`
fresh-target trials. It aborts before signing request `2^80`, so the
signing-query count is hard-capped at the official NGCC evaluation ceiling.

For CEDRUS-alpha-160f, retaining one fixed six-bit complete-address prefix and
optimizing the rigorous query count gives:

```text
signing-query mean                 2^71.458
fixed public-HMSG budget           2^67.160
attacker HMSG calls Q+T             2^71.530
expected full-path table bytes     2^77.479
fully provisioned table bytes      2^79.175
returned signature bytes           2^85.703
returned signature bits            2^88.703
honest signing-service hashes      2^89.060
success lower bound                > 0.6321205588
```

These quantities have deliberately different units. The `2^71.530` statement
counts attacker public-HMSG calls: one recomputation for every acquired
signature plus the target trials. Signing-oracle queries remain the separate
`Q=2^71.458` quantity. Neither describes network traffic, signer computation,
or a run on this machine. No reviewed tradeoff makes every physical resource
smaller than `2^80`.

At the all-address `Q+T` optima, the largest expected exponent among the
separately reported resources is `2^100.852` honest-signer hash-family calls
for 512s. The separate maxima are `2^77.520` signing queries, `2^72.367`
public target hashes, `2^97.101` returned bits, `2^92.398` donor-table bytes,
and `2^83.075` record updates. These quantities have different units and are
not collapsed into one complexity number.

The generated low-memory 160f row preselects one complete address and retains
554 hits. Its high-probability acquisition budget is
`ceil(2*554*2^66)=2^76.113742` signing queries; the fixed public-HMSG budget is
`2^72.445408`, and attacker public-HMSG work `Q+T` is `2^76.222974`. The doubled
acquisition budget returns `2^90.358998` signature bytes and costs the honest
service `2^93.716231` hash-family calls. These values are generated in
`expected/hostile_complexity.json` and checked by `validate_release.py`.

At exactly `2^64` signing queries, 160f's mean one-target success is about
`2^-161.7365`; this mechanism does not break an explicitly enforced `2^64`
per-key lifetime. The submitted specification states no such maximum. The
official `2^64` provision is a minimum support requirement, while the NGCC
evaluation criteria allow up to `2^80` chosen-message signing queries.

## Submission-wide lifetime and counter audit

The bundled evidence audit covers the 53-page specification, both two-page
English and Chinese basic-information forms, all 16 reference/optimized
READMEs, all 16 source trees, and the specification's security-analysis
chapter. It found no maximum signatures-per-key value or mandatory key-rotation
rule. Section 3.2 instead introduces `q_sig` as the number of signing queries
overall and uses it without a stated cap in Equations (3.1)--(3.2). A deployment
that enforces retirement after `2^64` signatures falls outside this attack's
established range.

The authors' related ePrint 2025/2236 makes reduced capacity explicit for
different constructions in Section 5.5, “CEDRUS Supporting Less than 2^64
Signatures.” Its ordinary CEDRUS-alpha discussion in Section 5.2 and Appendix
R.3 keeps a `q_S`-parameterized EU-CMA reduction and imposes no cap on the NGCC
sets. Because those framework parameter sets are separate, this is supporting
evidence about documentation practice rather than a normative submission rule.

The exact PDF token `ctrFTS` occurs only at Algorithm 20, line 16. Equation
(1.3), Figure 1.14, and Tables 1.2--1.3 contain related dangling counter
notation, but no generation loop, acceptance predicate, verification check, or
forced-pruning distribution is specified. Algorithm 20 computes `HMSG` without
the counter; Algorithm 21 neither parses nor checks one and uses a counter-free
length equation; Table 1.1 and Equation (4.1) publish counter-free sizes. All
16 source trees serialize only `R`, hash `R || PK || M`, and define
`SPX_BYTES` without a four-byte term. An unconstrained public counter would be
another public grinding input, not a defense.

## Reduced end-to-end forgery

`scripts/toy_spec_verifier.py` is a hostile reviewer's independent reduced
implementation of the relevant specification relation. Its deterministic
replay obtains 26 ordinary hedged signatures, combines coordinates from three
distinct donor messages, and produces a signature accepted on a message never
sent to the signing oracle. `scripts/full_toy_forgery.py` supplies a second,
fuller reduced hypertree implementation and explicitly verifies that no one
acquired transcript covers its coordinate-mixed target. The replays require
rejection after:

1. changing the message;
2. changing serialized `R`;
3. changing a FORC authentication node;
4. changing the hypertree suffix;
5. attempting to traverse a chain backwards; and
6. substituting an opening from another complete address.

The reduced hash instantiation is an ideal-primitive stand-in. It tests the
complete structural verification relation; it is not a full-parameter attack
execution.

## Full-parameter FORC-level splice

`scripts/full_parameter_forc_splice.py` uses the exact submitted
`(n,h,a,k,w')` values and full complete-address geometry for all eight sets. At
one address it constructs complete FORC trees, produces three valid digest
openings, advances and mixes coordinates from all three donors, and confirms
that the mixed opening reconstructs the unchanged FORC public key. It repeats
the check under both the Algorithms 14--18 endpoint convention and the
one-position-shifted prose convention. Authentication-path, unadvanced-node,
wrong-address, and whole-donor controls all reject.

SHAKE256 supplies a deterministic ideal-primitive stand-in for this structural
test. This is a full-parameter FORC-level conformance experiment. It is not a
full CEDRUS-alpha signature forgery and does not instantiate the astronomical
signature acquisition or public-target search.

## Repaired-native conformance

The submitted implementations have three public source deviations: 160-bit
WOTS truncation, eight-bit FORC address truncation, and hash/PRF differences.
The attack does not use them. `vendor/spec-repaired-256f/` is a bundled copy of
the 256f reference source with only the repairs recorded in
`SPEC_REPAIRS.patch`. `vendor/submitted-pristine-256f/` preserves the exact
submitted bytes, including CRLF line endings and the missing terminal newline
in `thash_sm3_simple.c`. This one command deterministically normalizes those
text details, applies the patch, and byte-compares the result with the bundled
repaired tree:

```sh
python3 scripts/replay_spec_repairs.py --output build/spec-repair-replay
```

`run_all.sh` performs that replay automatically and compiles the native check from
the replayed tree. The native check covers ordinary hedged signing,
verification, the published 43,296-byte signature size, malformed lengths,
message and transcript mutations, independent wrong keys, full-width FORC
chain addresses, the Table 1.2 PRF input, and full constant-sum WOTS message
handling. See `SPEC_CONFORMANCE.md`.

The source archive and specification PDF are not duplicated here:

```text
b90559ca94bda0130420f91fa52eeb242063a57188c766037c1b234ec3af563b  sign-04.zip
7be965ae53188beec23ca4543743402509e2ae1880630b19ab1dbd29b4d70e03  sign-04-spec.pdf
```

The bundled submitted source retains its original licensing terms. No broader
license is granted by this package.

## Main files

- `scripts/hostile_complexity.py`: exact first and second moments,
  concentration bounds, all-set optimization, fixed-address check, and 160f
  resource tradeoffs;
- `scripts/toy_spec_verifier.py`: independent reduced verifier, ordinary
  signing oracle, coordinate-mixing forgery, and negative controls;
- `scripts/full_toy_forgery.py`: second reduced hypertree forgery with explicit
  whole-transcript noncoverage and additional authentication controls;
- `scripts/full_parameter_forc_splice.py`: all-eight-set, full-parameter
  FORC-level coordinate-splice and endpoint-convention check;
- `scripts/validate_release.py`: release invariant checks;
- `scripts/replay_spec_repairs.py` and `vendor/submitted-pristine-256f/`:
  byte-exact replay of the documented source repairs;
- `native_check.c` and `vendor/spec-repaired-256f/`: native conformance run;
- `expected/`: byte-for-byte expected JSON outputs;
- `evidence/HOSTILE_REVIEW.md`: sealed independent hostile review;
- `evidence/FROZEN_OBJECTIONS.md`: objections frozen before that reviewer
  inspected the proponent analysis;
- `evidence/SPEC_LIFETIME_COUNTER_AUDIT.md`: exhaustive submitted-document,
  source-tree, KAT, lifetime, and counter-remnant audit;
- `SPEC_CONFORMANCE.md` and `SPEC_REPAIRS.patch`: specification choices and
  exact source repairs;
- `run_all.sh`: the single full replay entry point (`run.sh` is a compatibility
  wrapper); and
- `IMMUTABLE.SHA256SUMS`: files checked before every replay.

The hostile review passed with mandatory narrowing. The original audit report,
before replacing host-local reproduction paths in the packaged copy, has
SHA-256:

```text
32b915adafae79c53cf2a808f97fa8bc17b2af0ab1bf67a884efc44de08bc4de  original hostile-review report
```

The packaged copy changes only those reproduction paths and is sealed under
its release hash in `IMMUTABLE.SHA256SUMS`.

## Prior art and novelty boundary

The generic attack mechanism is prior art. CEDRUS-alpha Section 3.2 already
models repeated FORC instances and gives an approximate one-target coverage
probability. Abri and Katz, IACR ePrint 2025/2069, Equation (2), explicitly
multiplies the corresponding success probability by the number of public hash
trials. The narrow result reproduced here is the exact consequence for the
eight submitted CEDRUS-alpha parameter sets: public-`HMSG` optimization,
second-moment concentration, explicit coordinate mixing, complete resource
accounting, and the absence of a per-key cap that excludes the attack under
the official evaluation budget.

## Provenance and review status

The attack, derivation, implementations, experiments, manuscript, and release
package were produced by OpenAI Codex using Daybreak Blue at Ultra reasoning
effort during an AI-run audit of NGCC signature candidates. A separately
instructed hostile-review agent independently reconstructed the equations,
implemented a reduced verifier, recomputed the bounds, and accepted the result
only with the scope and resource qualifications stated above. No human
cryptanalyst has independently reviewed or reproduced the result at the release
date.

## Computational resources

The computations were performed on the Norwegian Research and Education Cloud
(NREC), using resources provided by the University of Bergen and the University
of Oslo.

The companion disclosure manuscript is available as
[`CEDRUS-alpha_Attack_Description.tex`](../CEDRUS-alpha_Attack_Description.tex)
and
[`CEDRUS-alpha_Attack_Description.pdf`](../CEDRUS-alpha_Attack_Description.pdf).
