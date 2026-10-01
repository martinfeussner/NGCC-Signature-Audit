# Prior-art checkpoint

Checked: 2026-10-01 16:28 UTC, after the mathematical hypotheses were frozen
for independent review and immediately before release finalization.

## Qing Luan public inventory

The current ngcc.dev security index and candidate page list `sign-20-1`, a
Medium/design proof gap concerning Qingluan-128 quantum accounting. It does not
concern DRBG rollback, repeated round masks, witness extraction, or forgery.

* https://ngcc.dev/reports/index.html
* https://ngcc.dev/reports/sign-20.html

Best-effort exact-name and mechanism searches of the NIST PQC Forum, web/PKC
results, IACR ePrint, and general web indexes found no public Qing-Luan-specific
complete-pre-signature-DRBG-state-rollback extractor as of the checkpoint.
This is a negative search result, not a definitive novelty guarantee.

## Closely related generic and CROSS literature

* Aranha, Orlandi, Takahashi, and Zaverucha, *Security of Hedged Fiat--Shamir
  Signatures Under Fault Attacks*, EUROCRYPT 2020 / ePrint 2019/956, studies
  the catastrophic effect of repeated Fiat--Shamir randomness, names a
  randomness-reuse attack, and applies fault analysis to Picnic2.  It makes the
  generic mechanism prior art.
  https://eprint.iacr.org/2019/956
* Mondal et al., *ZKFault: Fault attack analysis on zero-knowledge based
  post-quantum digital signature schemes*, ePrint 2024/1422, recovers CROSS
  secrets by faulting its tree disclosure.  It is relevant CROSS-specific
  fault/key-recovery prior art, but the fault surface and extraction mechanism
  differ from two valid rollback-repeated Qing Luan transcripts.
  https://eprint.iacr.org/2024/1422
* Jendral, Dubrova, Guo, and Johansson, *Correction Fault Attack on CROSS under
  Unknown Bit Flips*, TCHES 2026(2), ePrint 2025/1885, recovers CROSS keys by
  faulting the public parity-check matrix.  It is not a repeated-randomness
  attack.
  https://eprint.iacr.org/2025/1885
* The CROSS specifications document indexed per-round salt/domain separation
  and the general five-pass Fiat--Shamir construction from which Qing Luan is
  adapted.  Qing Luan's own supporting `protocol_reference.md` expressly
  discusses special-soundness witness extraction from related transcripts.
  https://www.cross-crypto.com/CROSS_Specification_v2.2.pdf
* NIST's signature evaluation criteria separate ordinary EUF-CMA from the
  desirable misuse-resistance property and specifically mention catastrophic
  failure under RNG malfunction or nonce reuse.  This supports the narrow
  classification used here.
  https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/evaluation-criteria/security-(evaluation-criteria)

## Narrow novelty assessment

Repeated-randomness extraction in Fiat--Shamir signatures is established prior
art. Fault attacks recovering CROSS witnesses are also prior art. The only
potentially new point identified here is the exact Qing Luan complementary
opening mechanism

```
eta = Expand(Seed_i, Salt, i) + v_i mod 7,
```

where one rollback transcript publicly serializes `Seed_i` and the other
serializes the matching `v_i`. If both fixed-weight second challenges are
identical, the independent same-branch fallback uses

```
e'_i=(y_i-y'_i)/(beta_i-beta'_i),  e=g^{v_i} e'_i,
```

together with the fact that sections 3.3.4 and 3.3.6 expressly claim robustness
for essentially the complete pre-signature DRBG state-rollback scenario that
repeats both the hidden root and public salt and makes these complementary or
repeated type-0 responses available. Repetition of either value alone is
insufficient. Any disclosure must keep the novelty claim at that
Qing-Luan-specific level and must not imply an ordinary fresh-randomness
EUF-CMA break. If those robustness statements are withdrawn, the mechanism
should instead be classified as a conditional fault/caller-misuse attack.
