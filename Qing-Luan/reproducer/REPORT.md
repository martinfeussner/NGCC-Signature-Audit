# Hostile review of the provisional Qing Luan rollback attack

Date: 2026-10-01 UTC  
Reviewer role: independent adversarial validation; objective was to disprove the
provisional result.

## Verdict

The provisional algebra survives hostile review, but only under its explicit
randomness-failure prerequisite.

| Possible claim | Verdict | Reason |
|---|---|---|
| Ordinary fresh-randomness EUF-CMA break | **FAIL** | The attack needs two different-message signatures produced after complete pre-signature DRBG state rollback to the same state immediately before both signing calls. A normal signing oracle supplies fresh randomness, and different-state controls rejected extraction. |
| Conditional complete pre-signature DRBG state-rollback robustness break | **PASS** | Two valid signatures produced after complete pre-signature DRBG state rollback to the same state immediately before both signing calls recover a full equivalent signing witness in polynomial time and yield a verifier-accepted fresh-message forgery at all four levels. The rollback repeats both the hidden root and public salt; either repetition alone is insufficient. Sections 3.3.4 and 3.3.6 expressly claim robustness for essentially this scenario. |
| Pure caller misuse, with no contradicted scheme claim | **FAIL as the exclusive classification** | Fresh randomness is a normal precondition, but the submitted specification separately discusses complete DRBG reset across different messages and declares it robust. If those statements are withdrawn, “caller misuse/fault attack” becomes a fair classification. |
| Implementation-only artifact | **FAIL** | The attack passed after repairing the submitted signer/verifier to the PDF's indexed-leaf and one-based-domain semantics. It also passed the untouched source as corroboration. |
| Invalid/provisional false positive | **FAIL** | A separately written public-input extractor, public relation checks, fresh witness-only signer, ordinary verifier, negative controls, fresh keys/messages, and sanitizer runs all support the result. |

The narrow defensible statement is:

> Qing Luan has a practical conditional robustness break under complete
> pre-signature DRBG state rollback to the same state immediately before both
> signing calls on two different messages.  The
> rollback must repeat both the hidden root and public salt; it reveals an
> equivalent signing witness and permits arbitrary fresh-message forgery.  This
> does not break ordinary EUF-CMA with fresh independent signing randomness.

## Exact protocol equations

All coordinates below are over `F_127`.  Let `z=7`, `g=2`, and
`E=<g>={1,2,4,8,16,32,64}`.  Key generation samples

```
eta in Z_7^n,       e = g^eta in E^n,
H = [V | I_(n-k)],  s = e H^T,
pk = (Seed_pk, s).
```

The secret key is a seed that regenerates `eta`; an exponent vector `eta` or
restricted vector `e` satisfying the public relation is an equivalent signing
witness even if it is not the original secret seed.

For round `i`, the signer expands a per-round seed to
`(eta'_i,u'_i) in Z_7^n x F_127^n` and computes

```
v_i  = eta - eta'_i mod 7,
u_i  = g^{v_i} odot u'_i,
s'_i = u_i H^T,
y_i  = u'_i + beta_i g^{eta'_i}.
```

The first challenge `beta_i` is a nonzero element of `F_127`.  The fixed-weight
second challenge makes `w` rounds type 1 and `t-w` rounds type 0.  A type-0
serialized response contains `(y_i,v_i,cmt1_i)`.  Its public verification
identity is

```
(g^{v_i} odot y_i) H^T - beta_i s = s'_i.
```

This identity follows because
`g^{v_i} odot g^{eta'_i}=g^eta=e`.

## Extraction proof

Complete pre-signature DRBG state rollback to the same state immediately before
both signing calls repeats both sequential DRBG outputs, `master_seed` and `Salt`. The
attack requires both values to repeat; either repetition alone is insufficient.
The specified indexed-leaf
derivation therefore repeats every per-round seed, so both signatures use the
same `eta'_i`, `u'_i`, and `v_i`.

Let `B` and `B'` be the type-1 positions in the two fixed-weight second
challenges. If `B != B'`, their equal cardinalities guarantee a cross-branch
position. At such an index, one signature serializes `Seed_i` in its type-1
opening and the other serializes the matching `v_i` in its type-0 opening.
Public expansion of the seed gives `eta'_i`, and therefore

```
eta = eta'_i + v_i mod 7.
```

One cross-branch position recovers every coordinate directly. The extractor
checks every cross-branch candidate against `e H^T=s` and requires all of them
to agree.

If `B=B'`, all type-0 positions are shared and an affine fallback remains. For
any round opened type 0 in both valid signatures with
`beta_i != beta'_i`, public responses give

```
y_i  = u'_i + beta_i  g^{eta'_i},
y'_i = u'_i + beta'_i g^{eta'_i}.
```

Subtracting and dividing in `F_127` gives the full vector

```
e'_i = g^{eta'_i} = (y_i-y'_i)/(beta_i-beta'_i).
```

The same response includes `v_i`, hence

```
e = g^{v_i} odot e'_i = g^eta.
```

One usable affine round recovers all `n` coordinates. Each coordinate has a trivial
seven-entry discrete logarithm, yielding an exponent witness `eta`.  The
extractor rejects unless every `e'_i` and `e` coordinate lies in `E` and
`e H^T=s`.  All other usable overlapping rounds must produce the identical
witness.

This is not recovery of the original `Seed_sk`.  It is recovery of an
equivalent signing witness with complete signing capability.

## Success probability

For the primary extractor, if `B` and `B'` are independent uniform
fixed-weight type-1 sets, cross-branch extraction fails exactly when they are
equal:

```
Pr[cross-branch failure] = 1 / C(t,w).
```

The corresponding negative base-2 logarithms are 165.543619, 334.510906,
502.320455, and 671.306477 for the four profiles. These are ideal-model values,
not exact probabilities for conditioned serialized signatures.

If this fixed-weight collision occurs, the affine fallback below applies.

Let `a=t-w` be the number of type-0 rounds in each signature.  In the ideal
model where the two fixed-weight challenge sets are independently uniform, the
intersection size `J` has the hypergeometric law

```
Pr[J=j] = C(a,j) C(t-a,a-j) / C(t,a).
```

The `beta` values are uniform in the 126 nonzero field elements.  Conditional
on `J=j`, every overlap is unusable with probability `126^{-j}`.  Therefore the
exact ideal-model failure probability is

```
sum_j C(a,j) C(t-a,a-j) / C(t,a) * 126^{-j}.
```

`success_probability.py` evaluates this as exact rational arithmetic before
decimal conversion:

| profile | `(n,k,t,w)` | type 0 | expected overlap | ideal success |
|---|---:|---:|---:|---:|
| QingLuan-128 | `(127,76,256,212)` | 44 | 7.562500 | 0.9998867716727768570 |
| QingLuan-256 | `(251,150,512,424)` | 88 | 15.125000 | 0.9999999874511553011 |
| QingLuan-384 | `(370,221,763,631)` | 132 | 22.836173 | 0.9999999999988826237 |
| QingLuan-512 | `(491,293,1018,842)` | 176 | 30.428291 | 0.9999999999999998815 |

These affine success probabilities are exact only in the stated independent
ideal-challenge model, not exact
claims for the concrete SM3-conditioned serialized transcript distribution.

A layered explanatory model also accounts for finite `2*lambda`-bit digest
collisions. Let `q=2^(-2*lambda)`, `D=C(t,w)`,
`d=q+(1-q)q`, and `c=q+(1-q)/D`. Then

```
P_cross_fail    = d + (1-d)c,
P_combined_fail = d + (1-d)c / 126^(t-w).
```

This model is dominated by the digest layers, at roughly 2^-255, 2^-511,
2^-767, and 2^-1023. It too is an abstraction because the concrete
digest-to-fixed-weight map need not have perfectly balanced preimages.

## Independent implementation

The new `hostile_review.c` was written independently of the provisional
harness. Its affine attack entry point

```
extract_public(eta, stats, pk, m1, sig1, m2, sig2)
```

receives only a public key, two distinct messages, and two serialized
signatures. It receives no secret key, expected witness, DRBG seed/state,
hidden root, unexposed round seed, nonce, or instrumented signer value. It first calls the ordinary
verifier on both inputs, derives both challenge vectors from public fields,
parses only serialized type-0 responses, performs the equations above, and
checks restricted membership and `eH^T=s`.

`forge_with_eta` takes only `(pk,message,eta)` and implements the ordinary
signing equations from the recovered witness.  It has no secret-seed argument.
The resulting signature is checked by the ordinary verifier on an unqueried
message.

The release's `combined_extractor.c` independently parses both opening types.
It verifies both source signatures, tries every cross-branch position, checks
the first candidate against the public relation, and requires all later
candidates to be byte-identical. It then checks every usable affine candidate as an independent fallback
and consistency test. Its only per-round seed inputs are the public seeds
already serialized by type-1 openings. `witness_signer.inc` is parameterized so
the PDF-aligned build uses indexed leaves and one-based round domains while the
untouched-source build uses the source's unindexed leaves and zero-based
domains.

The producer/control portion reinitializes the submitted deterministic DRBG
before each of the two signing calls.  A separate replay check independently
draws the first `master_seed` and second `Salt` twice from the same initial
state, verifies both pairs are equal, and verifies the predicted Salt equals
the serialized Salt.  Those values are never passed to the extractor.

## Specification alignment

The main experiment began from fresh copies of the extracted submitted source.
Before adding the harness, `apply_spec_alignment.py` made only these semantic
repairs required by PDF sections 1.8--1.10:

1. derive each `Seed[i]` from an independent
   `DOMAIN_SEEDLEAVES || master_seed || Salt || LE16(i)` expansion rather than
   slicing one unindexed XOF stream;
2. use one-based round numbers in every `i+c` signer/verifier domain.

`SPEC_ALIGNMENT.patch` records the complete change for all profiles.  The
submitted `3t+1/2/3` key-expansion constants were retained because the supplied
`protocol_reference.md` explicitly requires them, resolving the abbreviated
main-PDF equations.

The `pristine/` copies compare byte-for-byte with the extracted submitted
source except for added hostile-review executables.  Their signer/verifier were
not patched.  They were tested separately only as corroboration.

## Results

The principal API-PKC runs used distinct reproducible 64-byte KAT seeds for
every key and message pair.  Every trial did all of the following:

* generated a fresh key;
* made two valid different-message signatures after complete pre-signature
  DRBG state rollback to the same state immediately before both signing calls,
  repeating both the hidden root and public salt;
* recovered and publicly validated an equivalent signing witness;
* forged an unqueried message and obtained ordinary-verifier acceptance;
* ran every negative control below.

| route and semantics/backend | 128 | 256 | 384 | 512 |
|---|---:|---:|---:|---:|
| affine / PDF-aligned / API-PKC DRNG | 32/32 | 8/8 | 4/4 | 4/4 |
| affine / PDF-aligned / standalone documented DRBG | 4/4 | 4/4 | 2/2 | 2/2 |
| affine / untouched submitted core / API-PKC DRNG | 4/4 | 4/4 | 2/2 | 2/2 |
| combined / PDF-aligned / documented DRBG | 1/1 | 1/1 | 1/1 | 1/1 |
| combined / untouched core / documented DRBG | 1/1 | 1/1 | 1/1 | 1/1 |

For the main PDF-aligned/API affine runs, type-0 overlap min/mean/max was
`3/6.844/12`, `12/16.375/21`, `18/22.250/28`, and `22/33.000/49` from 128
through 512.  A few overlapping rounds had equal `beta`, as expected, and were
skipped; all remaining candidates agreed.

For those affine runs, mean public extraction time, including two ordinary signature verifications,
was 0.0097/0.0524/0.1478/0.3127 CPU seconds at 128/256/384/512.  Peak resident
memory for complete batches was below 5 MiB.  The offline algebra is
`O(tn+rk)` small-field work and `O(tn+rk)` storage.  Online data is exactly two
signatures, or 37,440 / 148,496 / 329,880 / 585,632 signature bytes at the four
levels, plus the public key and messages.

## Adversarial controls

Every trial required all controls to behave as follows:

* **same-message complete pre-signature DRBG state rollback:** the signatures
  were byte-identical; every
  overlapping `beta` was equal; the low-level extractor found zero usable
  rounds and the public attack interface rejected equal messages;
* **different DRBG state:** both signatures verified, their randomness did not
  repeat, and extraction rejected;
* **one corrupted coordinate:** flipping one bit in the first serialized type-0
  `y` component made verification and extraction reject;
* **wrong public key:** a separately generated key rejected both verification
  and extraction;
* **wrong message:** verification and extraction rejected;
* **fresh-message binding:** the valid forgery for the unqueried message failed
  verification when paired with a previously queried message;
* **multiple candidates:** every usable complementary-opening and affine round
  recovered the same public-relation witness.

AddressSanitizer/UndefinedBehaviorSanitizer runs of the PDF-aligned standalone
affine harness and the combined cross-branch harness passed at levels 128 and
512. LeakSanitizer was disabled because the
PTY/ptrace environment does not support it.  The submitted API-PKC DRNG itself
triggers an unrelated rotate-by-32 UBSan warning in `drng.c`; reproducing with
the separate standalone DRBG rules that implementation artifact out as the
cause of the cryptanalytic result.

## Claim scope and specification language

PDF page 13, section 2.4.3, says that “a DRBG seed may be injected so the
whole flow replays deterministically” and that fixing the seed makes “the
entire signing process” reproducible.  PDF page 17, section 3.3.4, expressly
says: “If the DRBG is reset across two different messages, v2’s round seeds …
would repeat while the Fiat–Shamir challenges differ,” but nevertheless
concludes: “Qingluan demonstrates strong robustness under DRBG temporary-state
reuse.”  PDF page 18, section 3.3.6, states: “The DRBG state-reuse mechanism
exhibits robustness.”

The conclusion is false for complete pre-signature DRBG state rollback to the
same state immediately before both signing calls:
“drawn anew” does not imply a new value when the state has been restored.  The
rollback repeats both the hidden root and public salt; either repetition alone
is insufficient.  The ordinary fresh-randomness
precondition remains valid, so the result must never be summarized as a normal
single-oracle EUF-CMA break.  `SPEC_CLAIM_AUDIT.md` records the wording and
classification in detail.

## Prior art and novelty

Generic Fiat--Shamir randomness-reuse extraction is well established.  Aranha
et al. (EUROCRYPT 2020, ePrint 2019/956) explicitly analyze randomness-reuse
fault attacks and hedged signing.  ZKFault (ePrint 2024/1422) and a 2026 TCHES
correction-fault paper recover CROSS witnesses through different fault
surfaces.  Qing Luan's own supporting document discusses special-soundness
extraction.

The current ngcc.dev index has one unrelated Qing Luan proof gap about quantum
accounting.  Best-effort exact-name/mechanism searches found no public report of
this Qing-Luan-specific rollback equation and forgery.  Any novelty statement
must therefore be limited to the exact complementary-opening shared-mask
mechanism, with its type-0/type-0 affine fallback, and the contradiction of
Qing Luan's stated robustness claim for essentially complete pre-signature
DRBG state rollback. See
`PRIOR_ART.md` for URLs and qualifications.

## Separate 384/512 ceilings

The specified/standalone 32-byte Hash-DRBG selects output streams from at most
`2^256` states, limiting nominal 384/512 key and signing-randomness support.
Separately, QingLuan-512's `SM3(K||BE32(i))` squeeze uses a 128-byte key: after
two complete key blocks, one 256-bit chaining state determines the entire
stream.  `xof512_state_check.py` independently reconstructs all tested output
bytes from that state.

These are infeasible generic security ceilings, not practical attacks on this
machine, and they are not used by the rollback extractor.  The simple 512 XOF
argument does not transfer unchanged to the 96-byte QingLuan-384 XOF key.  See
`HIGH_LEVEL_CEILINGS.md`.

## Repair

The per-signature randomness derivation should be hedged with the signing key,
public key, and message, so external randomness rollback across different
messages cannot repeat round masks.  One minimal structural direction is to
derive the round root from a secret-keyed PRF over

```
domain || Seed_sk || pk_hash || H(message) || external_randomness
```

and derive Salt/root seeds from separate subdomains.  Binding `pk_hash` and a
message digest into every indexed round-seed derivation also blocks this exact
cross-message repetition, though the complete proof and byte format must be
updated.  Persistent anti-rollback counters can add defense in depth but should
not replace message/key binding.  Without such a change, sections 3.3.4 and
3.3.6 should withdraw the reset-robustness claims.

## Reproduction

From this directory:

```
./build_and_run.sh
```

This rebuilds the independent harness against all four PDF-aligned copies, all
four untouched core copies, both submitted DRBG paths where applicable, then
runs the exact-probability and XOF-state checks.  `EVIDENCE.json` records the
machine-readable verdicts and `SHA256SUMS` authenticates the review artifacts.
