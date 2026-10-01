# Audit of the submitted randomness-reuse wording

Source: submitted `Algorithm specifications.pdf` / local
`sign-20-spec.pdf`, extracted independently with MuPDF on 2026-10-01 UTC.

## Section 2.4.3

The section is titled “Randomized signing with a deterministic KAT mode.”  PDF
page 13 states:

> “Signing is randomized by a fresh Salt and root Seed; for KAT reproducibility
> a DRBG seed may be injected so the whole flow replays deterministically.”

The next bullet says:

> “Easy testing: by fixing the DRBG seed, the entire signing process can be
> fully reproduced, facilitating KAT testing.”

This establishes both the normal precondition (fresh randomness) and a
documented deterministic replay interface.  It does not turn a complete
pre-signature DRBG state-rollback attack into ordinary EUF-CMA.

## Section 3.3.4

The section is titled “Temporary Key Reuse,” but its body discusses temporary
randomness and DRBG resets.  PDF page 17 states, word for word:

> “If the entire DRBG is reset (generating the same master_seed) and signing
> the same message — with definitive and consistent signature results — no
> additional information is disclosed.”

It then states:

> “If the DRBG is reset across two different messages, v2’s round seeds —
> derived from master_seed and Salt, not from the message digest µ as in v1 —
> would repeat while the Fiat–Shamir challenges differ; v2 therefore keeps
> every round’s randomness unique through fresh per-signature master_seed and
> Salt (drawn anew each call, then wiped by secure_zero), not through
> message-derived seeds.”

The section concludes:

> “In conclusion, Qingluan demonstrates strong robustness under DRBG
> temporary-state reuse.”

Its material statements therefore are:

* every signature draws a fresh `master_seed` and `Salt`, so round randomness
  should not repeat;
* resetting the entire DRBG and signing the same message gives a repeatable
  signature and allegedly discloses no additional information;
* resetting the DRBG across different messages would repeat the round seeds
  while Fiat--Shamir challenges differ;
* nevertheless, the section concludes that Qing Luan has strong robustness
  under DRBG temporary-state reuse.

The third item correctly identifies the attack's prerequisite but the stated
conclusion does not follow.  With the submitted call order, complete
pre-signature DRBG state rollback to the same state immediately before both
signing calls repeats both sequential draws, first the hidden root
`master_seed` and then the public `Salt`.  It therefore repeats every
`(eta'_i,u'_i,v_i)`.  Repetition of either the hidden root or public salt alone
is insufficient.  A different message changes `beta_i`, and the two public
type-0 responses eliminate `u'_i` and disclose the full restricted witness.

The phrase “drawn anew each call” describes an invocation, not uniqueness after
state rollback.  It cannot justify the stated robustness conclusion.

## Section 3.3.6

PDF page 18 expressly states:

> “The DRBG state-reuse mechanism exhibits robustness.”

Complete pre-signature DRBG state rollback across different messages is the
scenario in which this summary is false.

## Scope decision

The ordinary signing algorithm requires fresh `master_seed` and `Salt` and the
normal EUF-CMA oracle does not grant complete pre-signature DRBG state rollback
to the same state immediately before both signing calls.
The experiment does not contradict ordinary fresh-randomness EUF-CMA.  It does
contradict the additional, explicit state-reuse robustness claim in sections
3.3.4 and 3.3.6.
The narrow classification is therefore a **conditional complete pre-signature
DRBG state-rollback robustness break**, not an unconditional signature break.

If those robustness statements are withdrawn and fresh randomness is treated
as an inviolable external precondition, the same behavior is more naturally
classified as caller misuse or a fault/randomness-failure attack.
