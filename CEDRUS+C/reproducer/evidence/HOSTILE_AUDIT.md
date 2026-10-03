# Hostile audit of CEDRUS+C same-address FORS accumulation

Date: 2026-10-03 UTC

## Verdict

The recovered same-bottom-address FORS+C accumulation attack is a valid
specification-level attack in the ideal-HMSG model used by the submission.  I
found no error in its probability, concentration, address semantics, strict
WOTS+C reasoning, or packed table formula.  An independent finite closed form
and a separate direct Poisson summation reproduce all four headline moment
pairs within `3.2e-13` bits.

It is not an attack that can be executed on this 64-vCPU, 125.77-GiB host in
reasonable time.  The recovered report's `b=6` and `b=11` profiles bound a
table by `2^80` **bytes**, not by this machine's RAM.  Sharding enough to fit a
fully provisioned table in actual RAM raises the 160f point to about `2^73.65`
interactions and the 160s point to about `2^79.81`.  The signature oracle would
have to return `2^87.81` or `2^92.21` bytes.  At the measured reference-signing
cost and ideal 64-core scaling, signing alone takes about `1.74e12` or
`1.29e15` years.  These figures distinguish an abstract security-claim break
from a physically runnable full attack.

The core FORS accumulation mechanism is not novel to the recovered artifact.
Section 3.2, equations (3.1)--(3.2), of the submitted specification explicitly
models repeated use of one FORS+C instance and gives the same

```text
[1 - (1 - 2^-a)^q]^k * 2^-a'
```

term.  The useful additions are the observation that serialized public
`(R,ctrFTS)` values let the forger repeat the target experiment, the
all-address concentration proof, prefix sharding, and concrete physical
accounting.

The attack uses ordinary distinct chosen messages and independent hedged
signer randomness.  It does not need an `R` collision, reset, repeated
randomness, deterministic mode, related key, weak key, caller formatting
mistake, omitted WOTS check, tree-index implementation bug, or a rare hash/key
condition.  Its probability statement is in the ideal-HMSG model adopted by
the specification's own concrete analysis.

## Frozen inputs

| input | SHA-256 |
|---|---|
| submitted specification PDF | `5ec5d9151e0208584e24af71c331d712995da452f1e4b75d4956aecf8da55b4b` |
| submitted archive | `a31de849cf0a0703a4e57decbdf4d97b100d00dc74756feaded2c04a7593e110` |
| repaired `verify_core.c` | `86d3048ade9c722c1a75d12f1e52416aa077fd8c24e07554567e3490ad902456` |
| repaired `hash_sm3.c` | `051a36d6a9107962af30b92a1e89bc22180f731cb417ab44cc2b71c39d05d09c` |
| NGCC x86 performance report | `e3384bc9a2110bcd101a0711c1f8926c7599723ef962914515044353614c2ba6` |
| NGCC evaluation criteria | `a28b3fb77d21a87ecc89606a9ade4daca5d8f5192b88ddbf116e7b6d81db37b8` |

The performance source is bundled as `evidence/perf_x86_1.md`.  It reports 513.49 million
mean cycles for CEDRUSC-160f signing and 8.65 billion for CEDRUSC-160s.  The
recovered analysis uses exactly those values.  The specification PDF has
separate submitter figures of 335,982,300 and 5,662,176,265 cycles; these do
not supersede the independent harness measurements.

The exact low-row parameters are:

| set | `n` | `h` | layers | `(a,k,a')` | WOTS+C | signature |
|---|---:|---:|---|---|---|---:|
| 160f | 20 | 66 | fifteen 4s, two 3s | `(7,30,9)` | two width-8, 38 width-16, `z_b=2` | 19,812 B |
| 160s | 20 | 67 | four 8s, five 7s | `(12,13,15)` | two width-32, 24 width-64, `z_b=6` | 9,460 B |

No per-key lifetime restriction was found.  Exact searches of the PDF text
found no `2^64`, `2^80`, `q_max`, `maximum signatures`, `per-key`, or `key
lifetime` limit.  Section 3.2 treats `q_sig` as a free signing-query variable.
The separate NGCC evaluation criteria assume at most `2^80` chosen-message
signatures when evaluating security strength.  This is an attacker-budget
assumption, not a signer-enforced per-key lifetime.  The recovered adversary
Poissonizes its acquisition count and aborts before that hard query cap; its
reported acquisition means are all below `2^80`.

## Why the splice is accepted

Let the complete bottom address be

```text
A = (layer=0, idxTree, idxLeaf).
```

The disjoint HMSG address fields contain exactly `h` bits.  For a fixed `A`,
coordinate `i`, and leaf `x`, the secret, leaf hash, authentication nodes, and
coordinate root are fixed by the key and address.  Every valid opening of any
leaf in coordinate `i` reconstructs the same ordered coordinate root
`T_(A,i)`.  Mixing one valid opening for each requested `(i,x_i)` at the same
`A` therefore reconstructs the same fixed FORS public key

```text
P_A = T_k(PK.seed, ADRS_FORS_ROOT(A),
          T_(A,0) || ... || T_(A,k-1)).
```

The bottom WOTS+C key at `A` always signs `P_A`, independent of the HMSG FORS
vector.  Every upper WOTS+C message is likewise a fixed structural root.  One
honest strict-valid hypertree suffix from `A` therefore authenticates any
same-address coordinate mixture.

Cross-address mixing does not work.  The full tree and keypair fields survive
the specification's compressed address, and FORS leaf, tree-node, and root
hashes are address and type separated.  Both full-parameter native controls
show that changing the complete address changes the reconstructed root.

The strict repaired verifier installs the serialized WOTS counter in the
`ROOT_HASH` address, recomputes HRoot, checks both the leading-zero condition
and constant digit sum, and only then reconstructs the WOTS public key.  Legal
digit vectors all have the same sum.  If public chain advancement takes legal
`x` to legal `y`, then `y_i >= x_i` for every coordinate and equality of sums
forces `x=y`.  The accumulation attack neither advances nor mixes WOTS
chains; it copies one strict-valid suffix.

The signature serializes `R` and `ctrFTS`.  Verification recomputes HMSG and
has no secret with which to test whether `R` came from PRFMSG.  For a fresh
message the forger can enumerate distinct 160-bit `R` values and 32-bit
counters.  Each raw HMSG trial independently has the forced bits, address,
and FORS vector required by the retained table.  The `2^192` serialized input
space is ample for every reported target budget.

## Independent probability derivation

Put `B=2^a`, and let an address receive `r` ordinary signatures.  For one
FORS coordinate, the expected covered-leaf fraction is

```text
g_r = 1 - (1 - 1/B)^r.
```

Conditional independence of the `k` disjoint HMSG coordinate fields gives

```text
E[Z | r] = g_r^k,
```

where `Z` is the fraction of all `B^k` vectors covered at the address.  For
two independently selected leaves of one coordinate,

```text
s_r = g_r/B
      + (1 - 1/B) [1 - 2(1 - 1/B)^r + (1 - 2/B)^r],
E[Z^2 | r] = s_r^k.
```

Poissonizing the total acquisition count with mean `2^q` makes every complete
address load an independent `Pois(lambda)` variable, exactly, with
`lambda=2^(q-h)`.  Write `alpha=1-1/B`, `beta=1-2/B`,
`A=2-1/B`, and `C=1-1/B`.  The independent closed forms used here are

```text
mu = sum_(j=0)^k (-1)^j binom(k,j)
       exp(lambda(alpha^j - 1)),

nu = sum_(i+j+l=k) k!/(i!j!l!) (-A)^i C^j
       exp(lambda(alpha^i beta^j - 1)).
```

These follow from the Poisson pgf `E[t^R]=exp(lambda(t-1))`.  A separate
direct Poisson sum, with an omitted-tail Chernoff bound below `2^-400`, gives
the same values.

| row | `q` | independent `log2(mu)` | independent `log2(nu)` | max difference from recovered result |
|---|---:|---:|---:|---:|
| 160f all addresses | 70.928 | -56.6395108337625 | -101.020076742210 | `1.5e-13` bit |
| 160f `b=6` | 71.220 | -50.9338633678311 | -91.3329691289970 | `4.3e-14` bit |
| 160s all addresses | 74.760 | -55.1387797879919 | -109.315485062730 | `2.9e-13` bit |
| 160s `b=11` | 75.587 | -44.9816079461866 | -89.4189483773584 | `3.2e-13` bit |

If a fixed prefix discards all but `M=2^(h-b)` addresses, one raw public
target trial has conditional success mass

```text
p(table) = 2^-a' * 2^-h * sum_(retained A) Z_A,
E[p]     = 2^(-a'-b) mu.
```

Independence across Poisson-split addresses gives

```text
Var(sum Z_A) / E[sum Z_A]^2 <= 2^(b-h) nu/mu^2.
```

Chebyshev bounds the probability of falling below half the mean by four
times that relative variance.  On the complementary event, fixing
`T=2/E[p]` raw target trials gives failure at most `e^-1`.  Thus the recovered
success lower bound

```text
(1 - 4 * 2^(b-h) nu/mu^2) * (1 - e^-1)
```

is correct.  Rounding `T` upward to an integer only improves it.

The exact WOTS+C membership probabilities also reproduce independently by
dynamic programming the central coefficient of the unequal-width digit
sum:

| set | central coefficient | valid probability |
|---|---:|---:|
| 160f | 5076644192508259298016710826210415141329832200 | 0.003473580913518225 |
| 160s | 99032245575810605513863765283027373737472800 | 0.0000677606121308699 |

## Storage audit

For one coordinate at address load `lambda`, the expected number of distinct
leaves is

```text
D = B(1-exp(-lambda/B)).
```

A complete stored opening occupies `((a+1)n+1)` bytes in the recovered
layout.  A suffix occupies

```text
S = d(4 + len*n) + h*n
```

bytes: 14,988 for 160f and 6,056 for 160s.  This reproduces the complete-path
table formula.

The compact forest formula is also correct.  At forest height `j`, an empty
subtree whose sibling is nonempty is a necessary frontier node.  Its expected
count is

```text
(B/2^j) [exp(-lambda*2^j/B) - exp(-lambda*2^(j+1)/B)].
```

Summing over `j`, storing one secret per disclosed leaf, the frontier hashes,
a `B`-bit bitmap per coordinate, and one suffix per occupied address gives the
recovered compact estimate.  The deterministic table provisions all `kB`
complete components at every retained address, so it is a conservative hard
payload bound.  A packed byte array can realize its odd 161-byte/261-byte
records without C-structure padding.

The recovered headline resource points are therefore numerically sound:

| set/profile | `log2 q` | `log2 T` | `log2(q+T)` | returned bytes | expected complete table | expected compact table | hard table |
|---|---:|---:|---:|---:|---:|---:|---:|
| 160f, all | 70.928 | 66.640 | 71.000 | 85.202 | 83.154 | 81.860 | 85.272 |
| 160f, `b=6` | 71.220 | 66.934 | 71.292 | 85.494 | 77.385 | 75.963 | 79.272 |
| 160s, all | 74.760 | 71.139 | 74.873 | 87.968 | 86.463 | 84.993 | 90.729 |
| 160s, `b=11` | 75.587 | 71.982 | 75.701 | 88.795 | 76.255 | 74.513 | 79.729 |

Those `b=6/11` rows are only **soft-`2^80`-byte** profiles.

## Actual-host profiles

`/proc/meminfo` reports 135,045,894,144 bytes, or `2^36.974659` bytes.  A
deterministically fully provisioned table first fits at `b=49` for 160f and
`b=54` for 160s.  The JSON result also contains safer `b=50` and `b=55` rows,
including exact RAM margins, target HMSG calls, measured HMSG ticks, returned
traffic, signer cycles, and the concentration success lower bound.

The minimum and safer-prefix rows are:

| set | `b` | `log2 q` | `log2 T` | `log2` HMSG parse+target calls | `log2` HMSG TSC ticks | hard table / RAM margin | RAM used | `log2` returned B | `log2` signer cycles | success lower bound |
|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|
| 160f | 49 | 73.538 | 69.937 | 73.6523 | 86.2001 | 77.30 / 48.47 GiB | 61.46% | 87.8121 | 102.4738 | 0.632079 |
| 160f | 50 | 73.611 | 70.066 | 73.7296 | 86.2774 | 38.65 / 87.12 GiB | 30.73% | 87.8851 | 102.5468 | 0.632045 |
| 160s | 54 | 79.000 | 78.593 | 79.8109 | 91.3216 | 106.08 / 19.69 GiB | 84.34% | 92.2076 | 112.0101 | 0.631807 |
| 160s | 55 | 79.000 | 79.593 | 80.3269 | 91.8376 | 53.04 / 72.73 GiB | 42.17% | 92.2076 | 112.0101 | 0.631494 |

The HMSG count includes one public parse per acquired signature plus the fixed
target budget.  TSC ticks use the local 5,988.144/2,917.959-tick 160f/160s
HMSG benchmarks.  The `b=50/55` rows halve the hard table again.  They do not
make the attack physically runnable; 160s `b=55` also pushes total
interactions above `2^80` at the optimizer's conservative `q<=79` boundary.

Using the authoritative NGCC harness costs, the minimum-prefix acquisition
alone is:

| set | `log2` signer cycles | ideal wall years, 64 cores at 2 GHz |
|---|---:|---:|
| 160f `b=49` | 102.474 | `1.74e12` |
| 160s `b=54` | 112.010 | `1.29e15` |

This idealization grants perfect scaling and omits traffic, allocation, and
table-update costs.  It is already fatal to host-scale feasibility.

Packed compact forests can reduce RAM, but not the query bottleneck.  The
independently optimized expected-size points are 160f `b=46`, `2^73.436`
interactions and `2^36.443` compact bytes, and 160s `b=50`, `2^79.010`
interactions and `2^36.904` compact bytes.  The latter leaves too little
runtime headroom; `b=51` uses `2^35.924` expected compact bytes for only
`0.113` extra interaction bits.

I also tested sharing identical upper-layer WOTS/authentication suffix chunks
among bottom addresses.  This is valid because the structural messages and
keys repeat hierarchically.  It changes the 160f `b=46` compact estimate from
`2^36.443` to `2^36.195` bytes and the 160s `b=50` estimate from `2^36.904` to
`2^36.896`.  It reduces neither required prefix and saves no query exponent;
FORS component storage dominates.

## Experiment evidence and limits

The recovered Python scaled experiment constructs a fresh-message mixed FORS
signature, attaches a strict-valid WOTS/XMSS suffix, and is accepted by its
strict repaired verifier.  Its negative controls reject a changed message, changed
`R`, cross-address suffix, wrong-address FORS component, FORS path tamper, and
illegal WOTS membership.

The two native experiments use the full submitted 160f and 160s FORS
parameters.  Each independently signs three vectors at one explicit complete
address, mixes coordinates from all donors, and reconstructs the same FORS
root.  Ten checks pass for each row, including wrong address, wrong target
index, secret tamper, and path tamper.  The recovered `run_all.sh` originally
omitted these programs; it and `validate.py` have now been fixed to execute
and require both results.

These native runs validate the full-parameter **component splice**, not a
full-parameter end-to-end attack transcript.  Producing ordinary signatures
that collide at useful complete addresses is exactly the astronomical
acquisition phase quantified above.  No experiment skips that phase and then
claims a physically obtained full forgery.

## Hostile findings

1. **No mathematical defect found.**  Independent moments, concentration,
   exact WOTS membership, table formulas, and optimizers agree.
2. **No address or strict repaired-verifier defect found.**  The complete bottom
   address is the required equivalence class, and one copied suffix is valid.
3. **The recovered memory label was easy to misread.**  `memory_bounded` means
   below `2^80` bytes.  It does not mean bounded by the available host.
4. **The recovered native validation was incomplete.**  Native splice source
   existed but was absent from `run_all.sh` and `validate.py`.  This is fixed.
5. **The cycle constants have valid provenance.**  They come from the pinned
   NGCC x86 harness report, not from the PDF.  The PDF figures are separate.
6. **Novelty is limited.**  The specification already contains the core
   accumulation probability, and public-target amplification is prior art.
   The candidate-specific parameter/lifetime consequence and rigorous
   all-address, sharding, and resource treatment are the meaningful additions.
7. **No host-scale optimization emerged.**  Compact forests, actual-RAM
   sharding, upper-suffix sharing, heavy-address selection, coordinate
   partitioning, and WOTS endpoint reuse do not remove the signing-query or
   traffic bottleneck.

## Reproduction

From the packaged `reproducer/` directory, run:

```sh
./run_all.sh
```

This regenerates the main analytic, independent cross-check, scaled forgery,
native splice, and validation results.  The independent cross-check imports no
code from the main resource analyzer.
