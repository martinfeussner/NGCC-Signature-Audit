# Independent hostile audit: CEDRUS+C ordinary-signature FORS accumulation

Date: 2026-10-03 UTC

## Verdict: PASS, with mandatory scope and resource qualifications

The candidate mechanism is a valid specification-level fresh-message forgery
in the ideal-`HMSG` model used by the submission.  It uses ordinary fresh
hedged signatures under one ordinary key, exact complete-bottom-address
collisions, same-address FORS coordinate splicing, one copied strict-valid
hypertree suffix, and public `R`/counter grinding for a never-signed message.
It does not use the submitted tree-index collapse, Algorithm 6's missing WOTS
membership check, reset or repeated randomness, a fault, related/weak keys, or
caller misuse.

I found no mathematical, address-binding, suffix-binding, verifier-origin, or
probability error.  An independent direct Poisson calculation reproduces the
four headline rows within `6e-12` bits.  Fresh rebuilds against the untouched
submitted FORS core pass at both 160f and 160s; the scaled forgery under the
strict repaired verifier and every negative control pass.

Three qualifications are mandatory in any disclosure:

1. The generic FORS accumulation mechanism is already stated in CEDRUS+C
   section 3.2, and public hash-query amplification is already analyzed by
   Abri--Katz.  Novelty is only the candidate-specific parameter/lifetime
   consequence, rigorous all-address concentration and sharding, concrete
   `q_S/q_H` optimization, and resource accounting.
2. The sub-`2^80` figures are signing-query plus public-`HMSG` interaction
   counts.  Returned data is about `2^88.2`--`2^91.8` bits for the reported
   profiles, and honest-signer work is about `2^99.9`--`2^108.6` measured
   reference cycles.  This is an abstract security-claim break, not a
   host-runnable full-parameter attack.
3. The submission states no per-key lifetime cap.  A deployment that enforces
   a lower cap such as `2^64` signatures per key is outside this attack range.

## Exact specification relation

Algorithms 16--18 define

```text
SK = (SK.seed, SK.prf, PK.seed, PK.root),
PK = (PK.seed, PK.root),
PK.root = xmssNode(SK.seed,0,h_(d-1),PK.seed,A_top).
```

Ordinary hedged signing samples a fresh `n`-byte `addrnd`, computes

```text
R = PRFMSG(SK.prf,addrnd,M),
D = HMSG(R,PK.seed,PK.root,M,ctrFTS),
```

and increments `ctrFTS` until the designated `a'` bits of `D` are zero.  The
next disjoint fields give the `k` `a`-bit FORS indices and the bottom address

```text
A = (layer=0, idxTree, idxLeaf),
|idxTree| + |idxLeaf| = h.
```

Conditioning on the disjoint forced field leaves `A` and the FORS indices
uniform in the ideal-`HMSG` model.

Put `B=2^a`.  Algorithms 12--15 define, for coordinate `i`, leaf `x`, and
global leaf index `u=iB+x`,

```text
s_(A,i,x) = PRF(PK.seed,SK.seed,ADRS_FORS_PRF(A,u)),
L_(A,i,x) = F(PK.seed,ADRS_FORS_TREE(A,u,height=0),s_(A,i,x)).
```

Those leaves form a fixed height-`a` Merkle tree with root `T_(A,i)`.  Its
address-specific compressed public key is

```text
P_A = T_k(PK.seed,ADRS_FORS_ROOT(A),
          T_(A,0) || ... || T_(A,k-1)).
```

A valid opening for any `x` in coordinate `i` at the same complete `A`
reconstructs the same `T_(A,i)`.  Consequently one may take coordinate `i`
from any donor that opened the required `(A,i,x_i)`: the ordered mixture
reconstructs the same `P_A`.  Mixing across a different tree or keypair
address changes the leaf/tree/root domains and fails.

Algorithm 17 signs `P_A` with the bottom WOTS+C key at `A`; every higher
WOTS+C message is likewise a fixed structural child root.  Therefore one
honest hypertree suffix for `A` authenticates every coordinate mixture that
reconstructs `P_A`.  This remains true under the strongest coherent repair of
Algorithm 6: the verifier installs the serialized WOTS counter, checks both
the leading-zero predicate and constant-sum membership, and then reconstructs
the WOTS key.  The attack does not advance or mix WOTS chains.  Indeed, legal
vectors have a fixed coordinate sum, so `y_i >= x_i` for all `i` and equal
sums imply `y=x`.

Algorithm 18 parses serialized `R` and `ctrFTS`, recomputes `HMSG`, checks the
forced bits, reconstructs `P_A`, and calls `verifyHT`.  It has no secret value
with which to check whether `R` originated from `PRFMSG`.  A forger is thus
entitled to enumerate distinct public `(R,ctrFTS)` values for a fresh message.
The 160-bit `R` field alone exceeds every reported target-search budget, so
counter-zero/source-counter conventions do not affect the attack.

## Attack and probability check

The adversary requests ordinary signatures on distinct chosen messages,
buckets them by exact `A`, retains one opening for every observed `(A,i,x)`,
and retains one honest hypertree suffix per used address.  For a never-signed
target message it enumerates public `R` values until the forced field is zero
and every selected leaf is present at the selected address, then serializes
the mixed FORS opening and copied suffix.

For `r` signatures at one address, let `Z` be the fraction of its `B^k`
vectors covered.  The exact conditional moments are

```text
g_r = 1-(1-1/B)^r,
E[Z|r] = g_r^k,

s_r = g_r/B + (1-1/B)
      * [1-2(1-1/B)^r+(1-2/B)^r],
E[Z^2|r] = s_r^k.
```

Poissonizing the total acquisition count with mean `2^q` makes all `2^h`
address occupancies independent `Pois(lambda)` variables, exactly, where
`lambda=2^(q-h)`.  Write `mu=E[Z]` and `nu=E[Z^2]`.  If a fixed prefix retains
`2^(h-b)` addresses, then a raw target trial has expected success

```text
E[p] = 2^(-a'-b) mu.
```

The relative variance is at most `2^(b-h) nu/mu^2`.  Chebyshev therefore
bounds the chance that the realized table mass is below half its mean by four
times this value.  On the complementary event, `T=2/E[p]` independent public
target trials fail with probability at most `e^-1`.  The resulting one-run
success lower bound is

```text
(1 - 4*2^(b-h)*nu/mu^2) * (1-e^-1),
```

approximately `0.63212` in all four rows.  The adversary aborts before the
hard `2^80` signing-query ceiling.  The Poisson upper-tail bounds for hitting
that cap have base-two logarithms below `-3.6e24`, so subtracting abort
probability does not change the displayed success.

My independent `independent_bounds.py` uses direct Poisson recurrence and
imports no candidate analysis.  It obtains:

| row | `log2(mu)` | `log2 T` | `log2(q_S+T)` | max delta |
|---|---:|---:|---:|---:|
| 160f, all addresses | -56.6395108337569 | 66.6395108337569 | 70.9999993561012 | `5.6e-12` |
| 160f, retain prefix `b=6` | -50.9338633678252 | 66.9338633678252 | 71.2921139693886 | `5.9e-12` |
| 160s, all addresses | -55.1387797879864 | 71.1387797879864 | 74.8727202855886 | `5.3e-12` |
| 160s, retain prefix `b=11` | -44.9816079461804 | 71.9816079461804 | 75.7009159432936 | `5.9e-12` |

## Resource separation

The following numbers are separate natural units; they must not be collapsed
into one headline "complexity."

| profile | `log2 q_S` | `log2` public trials | interactions | returned bits | hard table bytes | signer cycles |
|---|---:|---:|---:|---:|---:|---:|
| 160f, all | 70.928 | 66.640 | 71.000 | 88.202 | 85.272 | 99.864 |
| 160f, `b=6` | 71.220 | 66.934 | 71.292 | 88.494 | 79.272 | 100.156 |
| 160s, all | 74.760 | 71.139 | 74.873 | 90.968 | 90.729 | 107.770 |
| 160s, `b=11` | 75.587 | 71.982 | 75.701 | 91.795 | 79.729 | 108.597 |

Thus both low rows admit a constant-success adversary within the NGCC
`2^80` chosen-message query ceiling, but none of these full attacks can be run
on the present 64-vCPU/125-GiB host.  Honest signing is the largest displayed
resource, reaching roughly `2^100.2` cycles for 160f and `2^108.6` cycles for
160s in the memory-bounded profiles.  A full-parameter forgery was not run and
must not be claimed.

## Key-lifetime audit

`lifetime_scan.py` searched 667 extracted source/document text files,
including the English specification, English and Chinese basic-information
forms, all C/header/build text, and all 16 implementation READMEs.  All 16
READMEs are identical, with SHA-256
`fffa60d94194f9f8d58b1dff603a55c2256a0b11d26c6240eef1744cad19a880`.
It found no occurrence specifying a maximum signatures-per-key rule,
per-key lifetime, rotation requirement, or per-key cap.  The only source
`2^64` statement limits the number of addressable subtrees and is unrelated to
key lifetime.

Conversely, specification section 3.2 explicitly treats `q_sig` as "the
number of signing queries overall" and uses it as a free variable in equations
(3.1)--(3.2).  The English and Chinese basic-information forms contain only
candidate/submitter metadata.  The NGCC evaluation criteria permit access to
signatures for no more than `2^80` chosen messages.  The evidence supports the
precise wording: **the absence of a specified per-key lifetime cap places the
attack inside the official NGCC chosen-message query budget.**

## Experimental evidence and negative controls

- `run_all.sh` independently replayed the analytic, moment, strict toy,
  full-parameter native splice, and validation artifacts: `PASS` on every
  check.
- The scaled strict repaired-verifier model made 240 ordinary randomized
  queries under an independent key, forged a never-queried message by combining
  coordinates from three distinct donor queries, and passed the strict repaired verifier.  It rejects
  changed message, changed `R`, FORS path tamper, illegal WOTS membership,
  cross-address suffix, and wrong-address component controls.
- I rebuilt `native_fors_splice.c` with `-Wall -Wextra -Werror` directly
  against the untouched submitted 160f and 160s reference FORS sources.  Both
  reruns match the prior outputs byte for byte.  Each verifies three donors,
  shows that the mixed unseen vector reconstructs the same root, and rejects
  secret/path/index/address mutations.
- The native runs are full-parameter FORS-level conformance tests, not
  full-parameter end-to-end forgeries.  They bypass neither the required
  address collision nor the quantified acquisition phase.

## Specification/source boundary

The submitted source sets `tree=0` and has a bottom-height masking defect;
those implementation bugs are excluded.  The specification's full-width
`idxTree` and `idxLeaf` parsing is used.  Algorithm 6 omits strict WOTS+C
membership/counter handling; the strongest coherent repair, also enforced by
the submitted WOTS source, is used.  Algorithms 14/17 appear to serialize the
FORS counter twice, while Figure 1.14, Algorithm 18's length, published sizes,
and source use one counter; the coherent one-counter format is used.  Stale
PORS/FORS names and Algorithm 10/11 call-site typos are resolved by the defined
FORS and ordinary bottom-to-top hypertree algorithms.  None of these repairs
creates the fixed-address FORS relation or the attack.

## Prior art and novelty

The live NGCC page checked on 2026-10-03 listed only the distinct submitted-code
index-collapse attack for CEDRUS+C.  The submission itself already gives the
core same-instance accumulation term.  Abri--Katz, IACR ePrint 2025/2069,
gives the integrated occupancy mixture and public hash-query multiplier.
Hülsing--Kudinov--Ronen--Yogev, IACR ePrint 2022/778, introduces FORS+C and
notes the public replaceability of its serialized counter.  PQC-X reports the
separate specified WOTS encoding-check omission and source index collapse.
A best-effort current search found no public CEDRUS+C result with this exact
all-address concentration, sharding, parameter/lifetime consequence, and
resource table.

No claim that FORS accumulation or public target grinding is new would survive
hostile review.  A narrow candidate-specific claim does.

## Reproduction

From the packaged `reproducer/` directory:

```sh
./run_all.sh
```

The full evidence is under `evidence/`, frozen machine-readable outputs are
under `expected/`, and a fresh replay writes `results/latest/`.
