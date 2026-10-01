# Sealed combined hostile review: Qing Luan complete pre-signature DRBG state rollback

Date: 2026-10-01 UTC  
Role: independent hostile reviewer instructed to disprove or narrow the result

## Verdict

**PASS, but only as a conditional complete pre-signature DRBG state-rollback
robustness break.**  Two valid signatures under the same key on distinct messages recover
an equivalent signing witness and permit a verifier-accepted signature on an
unqueried message after complete pre-signature DRBG state rollback to the same
state immediately before both signing calls.  This rollback repeats both the
hidden `master_seed` and the serialized `Salt`.

The evidence does **not** establish an ordinary fresh-randomness EUF-CMA
attack.  If the submission's reset/state-reuse robustness statements are
withdrawn, the same mechanism should be classified as a fault or caller-misuse
attack.  The recovered object is the R-SDP exponent/error witness `eta`/`e`,
not the original compact secret seed `Seed_sk`.

## Exact equation and branch/domain audit

For every profile, the public relation is over `F_127` with restricted group
`E=<2>` of order seven:

```text
eta in Z_7^n,  e = 2^eta in E^n,  e H^T = s.
```

For one round the signer computes

```text
v_i = eta - eta'_i mod 7
y_i = u'_i + beta_i * 2^(eta'_i).
```

The PDF numbers rounds `i=1,...,t`.  It derives an independently indexed
`Seed[i]` from the hidden root, public Salt, and `i`, then expands that seed at
the public `i+c` domain.  A type-1 opening serializes `Seed[i]`; a type-0
opening serializes `(y_i,v_i,cmt1_i)`.  Consequently, at a complementary
opening position in two complete-pre-signature-DRBG-state-rollback
transcripts,

```text
eta = ExpandEta(Seed[i], Salt, i+c) + v_i mod 7.
```

The release's PDF-aligned code uses independently indexed one-based leaves and
the one-based `i+c` domain.  Its untouched-source build uses the submission's
unindexed leaf stream and zero-based domain.  The independent adversarial
harness tested both conventions and rejected decoding under the opposite
convention in every tested cross position.

If the fixed-weight branch vectors are identical, every type-0 position is
shared.  Whenever `beta_i != beta'_i`, the fallback is

```text
e'_i = (y_i-y'_i)/(beta_i-beta'_i) = 2^(eta'_i)
e    = 2^(v_i) * e'_i = 2^eta.
```

These equations have the signs and branch numbering used by the PDF, repaired
signer/verifier, and untouched source.  Every recovered candidate is compared
with the first publicly validated candidate, and that reference is checked
against `e H^T=s`.

## Rollback and public-input boundary

The submitted signing source calls `randombytes(master_seed,...)` followed by
`randombytes(salt,...)`.  Complete pre-signature DRBG state rollback to the
same state immediately before both signing calls repeats both sequential
outputs.  With
the same key this
repeats every `Seed[i]`, `eta'_i`, `u'_i`, `v_i`, and commitment.  Merely
repeating the public Salt is insufficient if the hidden root differs.

The attack function receives only

```text
(pk, m1, serialized_sig1, m2, serialized_sig2).
```

It verifies both source signatures, rejects equal messages, parses public
openings, derives both challenge vectors, reconstructs candidate witnesses,
and checks the public relation.  The only round seed it consumes is a seed
already serialized by a type-1 opening.  The locally known secret and expected
witness appear only in producer/control assertions.  The witness-only signer
receives `(pk, fresh_message, eta)` and no secret seed; its output is accepted
by the ordinary verifier and rejected under a queried message or wrong key.

## Independent experiments

The official specification and submission archive reviewed here have SHA-256
digests:

```text
85edd9c2b0025cae82e4c9160f2286365279ce18bfde062d3586f17b4994f4bd  sign-20-spec.pdf
2eb8f3ed205eb7c7e8b3108a997b59643d1aa5579035b8093b4ddbe051a48007  sign-20.zip
```

The release's 172-file pristine-source manifest verified.  Direct comparison
with a fresh archive extraction found no core-source differences; only the two
archive-provided `.exe` files were intentionally absent from the release copy.

The final release manifest and clean-copy replay are recorded in
`EVIDENCE.json`.  The replay built all four profiles and passed:

* PDF-aligned signer/verifier with the submitted API DRNG;
* PDF-aligned signer/verifier with a separate implementation of the documented
  DRBG;
* byte-for-byte untouched submitted core semantics with the API DRNG;
* the combined cross-branch extractor under both PDF-aligned and untouched
  semantics;
* fresh-message forgery and all packaged negative controls;
* ASan/UBSan builds of the combined extractor (including its affine-candidate
  path) at 128 and 512;
* the exact probability scripts and the separate QingLuan-512 XOF-state check.

My final independent attack-code clean-copy replay, before the final
wording-only revision, used the then-sealed 368-entry manifest, verified the
172-entry pristine-source manifest, and produced 12 affine
profile/backend PASS rows and 10 combined PASS rows (eight ordinary and two
ASan/UBSan), and exited zero after 139.95 seconds with 45,548 KiB peak RSS.
The log contained no failure or sanitizer diagnostic.  The final public package
adds the 16:28 UTC prior-art snapshots and revises only documentation and
machine-readable wording; `REFERENCE_VALIDATION.log` preserves the earlier
full replay.  No additional large experiment was run for that wording-only
revision.

Separately, an audit-internal multikey run, not bundled in this public package,
records 32 independently seeded end-to-end cases: four key/rollback seed pairs
times four profiles times two semantics.  All 32 recovered the original honest
exponent witness, satisfied the public relation, and forged an unqueried-message
signature.  For every
case, every complementary-opening candidate agreed.  Additional controls
showed:

* the opposite one-based/zero-based domain convention did not validate;
* valid signatures with equal Salt but different hidden roots did not extract;
* valid signatures with one hidden root but different Salts did not extract;
* advancing-state, same-message, wrong-message, wrong-key, corrupted-input,
  and forgery-tamper cases rejected;
* the affine equation recovered the same witness.

The release was strengthened during this review.  Early snapshots had a
witness-only signer that silently retained the untouched source's leaf/domain
semantics in the PDF-aligned build, selected only the first cross candidate,
and contained a wrong-message control masked by a new equal-message guard.
Later snapshots also overstated the literal candidate-validation complexity
and corrupted a commitment byte while prose claimed a `y`-byte control.  The
sealed release fixes each issue: the witness signer is semantics-parameterized,
all cross and affine candidates must agree, the controls reach the intended
paths, the first candidate is publicly validated once and later candidates are
compared to it, and the combined corruption control locates and flips an
actual serialized type-0 `y` byte.

## Probability audit

Let `B,B'` be independent uniform weight-`w` type-1 sets.  Equal cardinality
means `B != B'` always supplies a complementary opening, so the exact failure
probability in this ideal fixed-weight model is

```text
Pr[B=B'] = 1/binom(t,w).
```

An independent exact-integer/Decimal recomputation gave the following
negative base-two logarithms:

| level | cross-only failure | digest-free combined failure | layered combined failure |
|---:|---:|---:|---:|
| 128 | 165.543618511657 | 472.543935145654 | 255.000000000000 |
| 256 | 334.510905806295 | 948.511539074287 | 511.000000000000 |
| 384 | 502.320455194396 | 1423.321405096385 | 767.000000000000 |
| 512 | 671.306477261196 | 1899.307743797182 | 1023.000000000000 |

The digest-free combined column multiplies by the conditional affine-fallback
failure `126^-(t-w)`.  It is not an honest concrete full-pipeline probability.
The layered column includes idealized finite `2*lambda`-bit message,
challenge-1, and challenge-2 digest collisions.  The manuscript correctly
labels both calculations as abstractions and does not claim they are exact for
conditioned serialized SM3 transcripts.  The older 32/8/4/4 empirical counts
and `success_probability.py` values concern the affine route; the release now
labels them separately from the combined cross-branch trials.

## Specification claim and novelty boundary

PDF section 2.4.3 documents deterministic whole-flow replay from a fixed DRBG
seed.  Section 3.3.4 expressly considers reset across different messages,
states that round seeds repeat while Fiat-Shamir challenges differ, and then
claims strong robustness under temporary DRBG-state reuse.  Section 3.3.6
again says the DRBG state-reuse mechanism is robust.  The experiment refutes
only that additional robustness claim.  Normal signing still calls for fresh
root and Salt values.

The 2026-10-01 16:28 UTC direct ngcc.dev snapshots list only `sign-20-1`, an
unrelated quantum-accounting proof gap.  A best-effort search found generic
Fiat-Shamir repeated-randomness/hedging work (ePrint 2019/956), CROSS fault
attacks (ePrint 2024/1422 and 2025/1885), and Qing Luan's own generic
special-soundness discussion.  No earlier Qing-Luan-specific public report of
the complementary `Seed[i]`/`v_i` rollback extractor was found.  This negative
search is non-definitive.  Any novelty claim must remain limited to the exact
candidate-specific mechanism and its contradiction of the stated robustness
property.

## Hidden assumptions and residual limits

1. The adversary or failure environment must induce complete pre-signature
   DRBG state rollback to the same state immediately before both signing calls.
   A normal fresh-randomness signing oracle does not supply this condition.
2. The two source signatures must use the same key and distinct messages.
   Same-message complete replay is byte-identical and gives no independent
   opening/equation.
3. Both the hidden root and public Salt must repeat.  Repetition of either
   value alone is insufficient.  Salt equality by itself is only a necessary
   public symptom, not proof of hidden-root equality.
4. The PDF specifies integer-valued indices but does not fully spell out their
   byte encoding.  The PDF-aligned experiment uses the submission's established
   little-endian 16-bit domain convention.  The attack is independent of that
   encoding choice so long as signer, verifier, and public expansion agree.
5. The identical-second-challenge fallback condition is too unlikely to sample
   naturally at full parameters.  Its algebra was checked on real shared
   type-0 rounds and by an independent equation self-test; the primary
   complementary-opening route was exercised end to end at every profile.
6. The ideal fixed-weight and layered hash probabilities are explanatory
   models.  They do not assert exact concrete probabilities for conditioned
   serialized signatures.
7. The search for prior art cannot prove novelty.

After the final validate-once optimization, reconstruction and candidate
consistency cost `O(t*n+r*k)` small-field work and comparable stored transcript
data, in addition to two ordinary signature verifications.  Only two source
signatures are needed.

No remaining mathematical, specification-conformance, public-interface, or
harness-artifact objection falsified the narrow conditional result.
