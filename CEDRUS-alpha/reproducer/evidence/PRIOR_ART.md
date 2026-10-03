# Prior-art checkpoint

Checked 2026-10-03 UTC.  This was a best-effort search of the live NGCC index,
the linked NGCC PKC Forum material, IACR ePrint, the SPHINCS/SPHINCS-alpha
literature, and general web indexes.  Direct fetching of the three linked PKC
Forum messages failed, so their scope was checked through the current ngcc.dev
summaries.

## Closest prior work

1. **The CEDRUS-alpha submission itself, Section 3.2.**  Equations (3.1) and
   (3.2) model the binomial occupancy of an `h`-bit FORC instance after
   `q_sig` signatures and give an approximate coordinate-completion term

   `p_FTS_Succ(q) = (1-(1-((W+1)/(2 W))/(2^a W))^q)^k`.

   In equivalent simplified notation, the inner one-donor probability is
   `(W+1)/(2*2^a*W)`.  The submission therefore already recognizes the generic
   same-instance forward-chain accumulation mechanism.  It does not state a
   per-key signing cap, does not give the signing-query/offline-search optima
   derived here, and does not reconcile its parameters with the NGCC `2^80`
   chosen-message evaluation ceiling.  In particular, Equation (3.2) is the
   coverage probability of one fresh public digest trial.  The section has no
   `q_H` variable and does not apply the amplification
   `1-(1-p_S(q_sig))^q_H` available from `q_H` distinct public `HMSG` inputs.

2. **Bernstein, Hülsing, Kölbl, Niederhagen, Rijneveld, and Schwabe, “The
   SPHINCS+ Signature Framework,” IACR ePrint 2019/1086.**  Section 4.1 defines
   interleaved target subset resilience, and Section 5 describes the generic
   event that a fresh message digest selects positions covered by earlier
   signatures at the same few-time instance.  That is the FORS predecessor of
   the accumulation/grinding part of this attack; it does not contain the
   CEDRUS-alpha chain-position calculation.

   <https://eprint.iacr.org/2019/1086>

3. **Zhang, Cui, and Yu, “SPHINCS-alpha: A Compact Stateless Hash-Based
   Signature Scheme,” IACR ePrint 2022/059.**  The archived paper introduces
   FORC by placing forward hash chains below the FORS leaves and analyzes it in
   the SPHINCS framework.  The generic forward-chain relation is consequently
   part of the construction's published background.

   <https://eprint.iacr.org/2022/059>

4. **NIST PQC Forum, “Request for feedback on possible SPHINCS+ variant,” 30
   November 2022.**  NIST explicitly noted that stateless hash-based signature
   parameters depend on the maximum number of signatures per public key and
   that the then-applicable NIST requirement was `2^64` signatures.  This is
   relevant background for treating the present result as a parameter/usage
   failure rather than a new generic attack family.

   <https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/LUczQNCw7HA/m/5aMVrsP6AgAJ>

5. **SPHINCS-alpha specification hosted by NIST.**  Its security discussion
   invokes ITSR and gives a query-dependent generic security formula.  It is
   useful corroboration that few-time-instance reuse and usage budgets are
   standard security-accounting issues in this family.

   <https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/round-1/spec-files/sphincs-alpha-spec-web.pdf>

6. **Abri and Katz, “Shorter Hash-Based Signatures Using Forced Pruning,”
   IACR ePrint 2025/2069.**  This paper is already reference [7] of the
   CEDRUS-alpha submission.  Its analysis treats signing-oracle histories and
   adversarial public-hash trials as separate resources and counts the joint
   accepted-and-covered event before applying the `q_H` trials.  It is prior
   art for the required `q_H` accounting and, more generally, for
   conditioning-safe coverage arguments.  Nothing here claims that multiplying
   a one-trial coverage probability by public trials is new.

   <https://eprint.iacr.org/2025/2069>

## Current CEDRUS-alpha public state

The live CEDRUS-alpha page on ngcc.dev listed exactly three findings at the
checkpoint: 160-bit WOTS truncation (`sign-04-1`), eight-bit FORC chain-address
truncation (`sign-04-2`), and incompatible hash instantiations (`sign-04-3`).
All three are implementation findings.  No CEDRUS-alpha design report or
parameter-lifetime forgery was listed.

<https://ngcc.dev/reports/sign-04.html>

Searches for `CEDRUS-alpha`, `CEDRUSα`, `FORC`, `Forest of Random Chains`, and
the attack's same-address/forward-chain terms found no public CEDRUS-alpha
parameter evaluation equivalent to the present all-address and fixed-address
tables.  The linked PKC Forum posts cover the same three implementation issues
summarized by ngcc.dev; their archive pages were not directly fetchable during
this checkpoint.

## Narrow novelty boundary

The generic idea “accumulate openings from repeated few-time keys and grind a
covered target” is prior art, CEDRUS-alpha's own Section 3.2 already writes down
an approximate one-trial probability for it, and Abri--Katz supplies prior art
for separate `q_H` accounting.  A defensible new contribution is only the
following candidate-specific result: exact chain-position coverage and
second-moment accounting for all eight submitted parameter sets, optimization
of the submitted parameters over `q_sig` and `q_H`, an explicit fresh-message
construction, a hard `2^80` signing-query strategy with constant success, full
accounting of interactions/data/memory/signer work, and reduced end-to-end
verification with hostile controls.  Any eventual disclosure must describe
this as a CEDRUS-alpha parameter and absent-usage-bound failure, not as the
discovery of subset reuse, FORC accumulation, or public-hash amplification.
