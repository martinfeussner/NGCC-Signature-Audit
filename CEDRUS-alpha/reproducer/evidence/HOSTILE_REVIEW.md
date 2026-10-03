# Hostile review of the CEDRUS-alpha FORC coordinate-mixing forgery

> **Final-release terminology note.** This earlier review used “total
> interactions” for the numerical sum `Q+T`. The final manuscript and README
> name that quantity attacker public-`HMSG` work: one digest recomputation for
> each of the `Q` acquired signatures plus `T` fresh-target trials. Signing
> queries are separately `Q`; traffic, storage, record processing, and
> honest-signer work remain separate.

Date: 2026-10-03 UTC

## Verdict

**PASS, with mandatory narrowing.** I failed to disprove the attack. The
same-complete-address FORC coordinate-mixing construction is a valid
fresh-message forgery against the coherently repaired CEDRUS-alpha
specification in its ideal-primitive model. It uses ordinary hedged signatures
with fresh signer randomness. It does not require a reset, repeated `R`, weak
key, deterministic mode, fault, related key, submitted-code address alias, or
other implementation defect.

The result is a parameter/lifetime break rather than a machine-practical
attack. At the best 160f interaction point, signing-oracle plus public-`HMSG`
interactions are about `2^71.24`, while returned traffic is about `2^85.41`
bytes (`2^88.41` bits) and the honest service performs about `2^88.77` hash
evaluations. A six-bit full-address-prefix shard gives a deterministic complete
donor-table payload below `2^80` bytes, but leaves traffic and signer work at
about `2^85.70` bytes and `2^89.06` hashes. No reviewed row makes every
physical resource smaller than `2^80`.

The generic mechanism is prior art. CEDRUS-alpha Section 3.2 already gives the
same-instance occupancy and one-target FORC coverage formula. Abri--Katz,
ePrint 2025/2069, Equation (2), explicitly multiplies the corresponding
one-target success by the number of public hash trials. The only defensible
novelty is the exact CEDRUS-alpha parameter consequence: adding the public
offline-`HMSG` grind, proving that the realized all-address table concentrates,
and observing that the submission gives no per-key lifetime cap that excludes
the resulting attack inside the official chosen-signature evaluation budget.

## Independent reconstruction

I wrote `FROZEN_OBJECTIONS.md` before opening the proponent directory. The
normative input was the submitted PDF, whose SHA-256 is
`7be965ae53188beec23ca4543743402509e2ae1880630b19ab1dbd29b4d70e03`.

Let the complete bottom FORC address be

```text
A = (layer=0, treeAddr=idxTree, keyPairAddr=idxLeaf).
```

The two variable fields contain `h-h_0` and `h_0` bits, respectively, so there
are exactly `2^h` complete addresses. For coordinate `i`, leaf `x`, chain
position `j`, `B=2^a`, and `W=w'`, the coherent Algorithms 13--18 define

```text
s_(i,x)      = PRF(PK.seed, SK.seed, ADRS_FTS_PRF(A,iB+x)),
C_(i,x)(0)   = s_(i,x),
C_(i,x)(j+1) = F(PK.seed, ADRS_FTS_CHAIN(A,iB+x,j+1), C_(i,x)(j)),
L_(i,x)      = C_(i,x)(W).
```

The `B` endpoint leaves form one height-`a` Merkle tree per coordinate. If its
root is `T_i`, the fixed address-specific public key is

```text
PK_FORC(A) = T_k(PK.seed, ADRS_FTS_ROOT(A), T_0 || ... || T_(k-1)).
```

For a digest coordinate `(x_i,ell_i)`, signing reveals
`C_(i,x_i)(ell_i)` and the authentication path for leaf `x_i`.
Verification hashes forward from `ell_i` to `W`, reconstructs `T_i`, compresses
all roots to `PK_FORC(A)`, and verifies the hypertree suffix at the same `A`.

Ordinary signing samples fresh `addrnd` and computes

```text
R      = PRFMSG(SK.prf, addrnd, M),
digest = HMSG(R, PK.seed, PK.root, M).
```

The verifier accepts the serialized `R` as a public hash input and does not
test whether it came from `PRFMSG`.

## Resolution of specification ambiguities

The PDF is not literally executable, but the repair needed here is not chosen
to create the attack.

* The `HMSG` type and one serialization line mention `ctrFTS`, but Algorithms
  20--21 do not define, parse, or check it; their signature-length equation and
  all published signature sizes omit it. The submitted signer also has no
  FORC rejection loop. The coherent resolution is the counter-free Algorithms
  20--21. If an unconditioned public counter is retained, it merely adds a
  public target-search input and four response bytes.
* There is no specified forced-pruning condition. Reading the stale counter as
  evidence for an unpublished rejection rule would invent a different scheme.
  Consequently ordinary ideal-`HMSG` digest chunks are uniform and independent
  as used below.
* Algorithms 20--21 say `FORS`/`PORS` at stale call sites; Section 1.9 and the
  formats unambiguously supply FORC.
* Section 1.2 omits the `k log_2 W` position bits from `m`; the later parser,
  Algorithms 16--21, implementation dimensions, and signature format include
  them. The later complete parser is used.
* Prose calls a chain `W` nodes including endpoints, while Algorithms 14--18
  operationally disclose positions `0,...,W-1` and authenticate endpoint
  `C(W)`. The attack uses only those verifier-valid positions and only hashes
  forward. Using the natural prose repair shifts the endpoint convention but
  preserves the same partial order on disclosed positions.

## Forgery proof

Collect signatures on distinct chosen messages through the ordinary randomized
signing API. Recompute each public digest and group responses by the complete
`A=(idxTree,idxLeaf)`. For every `(A,i,x)`, retain the smallest disclosed
position `ell`, its node, and its authentication path. Retain one complete
hypertree suffix for every occupied address.

Choose a message `M*` that was never queried. Enumerate distinct attacker-chosen
`R*` values and compute `HMSG(R*,PK.seed,PK.root,M*)`. Stop when the output
selects an address in the table and, for every coordinate, selects `(x_i*,ell_i*)`
with a retained donor satisfying

```text
x_i = x_i*  and  ell_i <= ell_i*.
```

Hash the donor node forward by `ell_i*-ell_i`, then copy that donor's path.
The verifier's remaining chain hashes reach the original endpoint for leaf
`x_i*`, and the path reconstructs the original `T_i`. The donors may differ by
coordinate because every correctly reconstructed `T_i` belongs to the same
fixed `PK_FORC(A)`. A copied suffix for `A` authenticates exactly this value.
The forged message is fresh and verification accepts.

No path is transplanted across leaves, coordinates, or addresses. No chain is
traversed backward. The FORC public key contains neither the message nor `R`;
these values only select disclosed positions and the complete address.

## Exact probability and concentration

For `r` donor signatures at one address and a uniform target coordinate, the
exact ideal-model covered fraction has mean

```text
g_r = (1/W) sum_(y=0)^(W-1) [1-(1-(y+1)/(BW))^r].
```

The `k` coordinate streams are independent conditional on `r`, hence a full
target has mean coverage `g_r^k`.

The calculation also uses the exact single-coordinate second moment. For two
ordered targets of positions `y,z`, put `m_r(s)=(1-s/(BW))^r`. Their joint
coverage probability is

```text
1-m_r(y+1)-m_r(z+1)+m_r(max(y+1,z+1))  if their leaves agree,
1-m_r(y+1)-m_r(z+1)+m_r(y+z+2)         otherwise.
```

Averaging over the ordered target pair gives `s_r`; a full vector has second
moment `s_r^k`.

The attack Poissonizes its signing count with mean `Q`, then aborts before
making more than `2^80` requests. This makes the `2^h` address occupancies
independent `Pois(lambda)` variables, `lambda=Q/2^h`. Define

```text
mu = E[g_S^k],  nu = E[s_S^k],  S <- Pois(lambda).
```

For the realized table's one-target success mass `P`,

```text
E[P] = mu,
Var(P)/E[P]^2 <= nu/(2^h mu^2).
```

Chebyshev therefore bounds `Pr[P<mu/2]` by
`4 nu/(2^h mu^2)`. On the complement, the fixed search budget
`T=ceil(2/mu)` succeeds with probability at least `1-e^-1`. Thus the attack
does not substitute an expected table for a guaranteed one. The Poisson sums
in `hostile_complexity.py` are cut beyond a recorded Chernoff tail. At the 160f
interaction optimum, the bad-table bound is below `2^-53.06`; the `2^80` abort
bound has base-two logarithm below `-8.9e24`.

### All-address results

The first numeric pair optimizes the expected count
`Q+1/mu`. The next three independently optimize the rigorous count
`Q+ceil(2/mu)` used for the success statement. Exponents are base two.

| set | expected `Q` | expected total | rigorous `Q` | rigorous `T` | rigorous total | bad-table bound |
|---|---:|---:|---:|---:|---:|---:|
| 160s | 74.350 | 74.449 | 74.415 | 70.593 | 74.514 | `<2^-62.89` |
| 160f | 71.115 | 71.188 | 71.165 | 66.878 | 71.237 | `<2^-53.07` |
| 256s | 76.625 | 76.690 | 76.670 | 72.237 | 76.735 | `<2^-64.23` |
| 256f | 72.110 | 72.156 | 72.140 | 67.248 | 72.188 | `<2^-54.93` |
| 384s | 76.070 | 76.115 | 76.100 | 71.159 | 76.146 | `<2^-62.38` |
| 384f | 74.405 | 74.442 | 74.430 | 69.213 | 74.468 | `<2^-60.30` |
| 512s | 77.495 | 77.533 | 77.520 | 72.367 | 77.560 | `<2^-62.68` |
| 512f | 76.125 | 76.157 | 76.145 | 70.790 | 76.180 | `<2^-61.81` |

Each rigorous row has success probability at least
`(1-bad_table_probability)(1-e^-1)`, less only the negligible signing-cap
abort probability.

### Independent fixed-address check for 160f

For `r=554` retained hits at one preselected complete address, the donor table
has mean covered fraction `2^-5.445408`. Paley--Zygmund proves

```text
Pr[table coverage >= half its mean] >= 0.247483.
```

Make `ceil(2*r*2^66)` signing queries, an exponent of `76.113742`. The hit
count has mean at least `2r`; multiplicative Chernoff gives failure at most
`exp(-r/4)<2^-199.81` to obtain `r` hits. Use `2^72.445408` public targets.
The total interaction exponent is `76.222974`, and the resulting one-run
success lower bound is `0.156439` minus the hit-collection failure. The fully
provisioned one-address payload is `2^19.175` bytes. This is slower in traffic
and signer work than the all-address route, but independently confirms the
same address-event and chain-coverage accounting without relying on a mean hit
count.

## Three resource-accounting views

The phrase “`2^71` attack” is correct only for oracle/public-hash interactions.
The following views must remain separate.

1. **Interaction-minimized 160f.** `Q=2^71.165` ordinary signing requests and
   `T=2^66.878` public candidates give `2^71.237` total interactions. Responses
   contain `2^85.410` bytes (`2^88.410` bits), the conservative complete-path
   table has expected size `2^83.25` bytes, and the honest service performs
   `2^88.767` PDF-counted hash evaluations.
2. **Attacker I/O/CPU-balanced 160f.** Optimizing the larger of response bits
   and public-`HMSG` evaluations gives `Q=2^70.085`, `T=2^87.269`,
   `2^87.330` response bits, expected complete-path table `2^82.402` bytes,
   and `2^87.687` honest-service hashes. If one charges one unit per input bit
   and one per `HMSG`, their sum is about one further bit larger; the table
   update count is only `2^74.892`.
3. **Honest-service-balanced 160f.** Optimizing the maximum of signer hashes,
   response-byte work, and target hashes gives `Q=2^70.065`,
   `T=2^87.631`, `2^87.310` returned bits, and `2^87.667` signer hashes.

These are alternative time/data tradeoffs, not resources simultaneously paid
at their separate optima. All remain far below the claimed 160-bit classical
level, but all exceed the user's soft `2^80` vicinity under at least one
physical accounting view.

### Six-bit address-prefix shard

For a fixed `b`-bit prefix, only `2^(h-b)` complete addresses are retained.
Table mass and expected memory fall by `2^b`; target work gains `b` bits. The
second-moment relative-variance bound gains the same factor `2^b` and still
concentrates strongly.

An independent optimizer for `b=6` gives:

| quantity | base-two exponent/value |
|---|---:|
| signing-query mean | 71.458 |
| fixed public-target budget | 67.160 |
| total interactions | 71.530 |
| expected complete-path table bytes | 77.479 |
| deterministic fully provisioned table bytes | 79.175 |
| returned signature bytes / bits | 85.703 / 88.703 |
| honest signer hashes | 89.060 |
| Chebyshev bad-table bound | `<2^-48.61` |
| success lower bound | `0.6321205588` up to negligible abort |

The deterministic table bound is

```text
2^(h-b) * [k*2^a*((a+1)n+1) + (d*len+h)n + 16] bytes.
```

It provisions one full-path donor record for every leaf and coordinate and one
complete suffix for every retained address. It does not assume Merkle-frontier
compression or average occupancy.

## Ordinary signing, freshness, and source independence

`toy_spec_verifier.py` is an independent reduced verifier written before the
proponent artifacts were inspected. It implements domain-separated FORC
chains, complete addresses, leaf-specific authentication paths, fixed
address-specific suffix authentication, attacker-chosen serialized `R`, and
fresh randomized signing. Its deterministic run made 26 ordinary hedged
queries and produced an accepted forgery on a never-queried message from three
distinct donor messages. It also rejected each of these controls:

* changed message;
* changed `R`;
* changed FORC authentication node;
* changed hypertree suffix;
* reversed chain direction; and
* an opening from a different complete address.

The submitted source was used only as a conformance check. It confirms forward
chain verification and ordinary fresh-`optrand` signing, but contains three
already public deviations: 160-bit WOTS truncation, eight-bit FORC chain-address
truncation, and hash/PRF instantiation mismatches. The proof and reduced
verifier use full-width PDF addresses, complete WOTS/FORC values, and the
specified domain organization. The attack neither benefits from nor needs any
of those bugs.

The proponent's repaired 256f native bundle and fuller reduced verifier were
inspected only after `FROZEN_OBJECTIONS.md` was sealed. Their passing results
corroborate this independent analysis; they are not the source of its proof or
probability formulas. A full-parameter forgery was not executed because the
derived resources are astronomical.

## Key-lifetime and evaluation boundary

The submitted specification and its basic-information form contain no maximum
signatures per key. Section 3.2 instead treats `q_sig` as a free variable. A
full-text search found no `2^64`, `2^80`, “maximum signatures,” or equivalent
per-key lifetime rule.

The official NGCC Evaluation Criteria, Section 1(2), evaluates chosen-message
attacks with no more than `2^80` signature queries:

<https://www.niccs.org.cn/niccs/Notice/1975896137741635584/tT7TSQiz.pdf>

The separate submission requirements, Section 2(2), require a signature key
pair to support at least `2^64` different messages:

<https://www.niccs.org.cn/niccs/Notice/lDop1mav.pdf>

The latter is a minimum support requirement, not an implicit maximum. The
Poissonized algorithm aborts before request `2^80`, so it always respects the
evaluation ceiling; for the 160f six-bit shard, the probability of that abort
is bounded by less than `2^(-8.5e24)`.

This distinction matters. At exactly `Q=2^64`, 160f's mean one-target success
is `2^-161.7365`, so this route does not defeat a deployment that explicitly
and enforceably retires every key at `2^64` signatures. Adding such a cap would
be a possible policy/parameter repair. It is not present in the submitted
scheme.

## Prior-art checkpoint and novelty limit

The current CEDRUS-alpha page was checked on 2026-10-03:

<https://ngcc.dev/reports/sign-04.html>

It lists only the three implementation findings just named and does not list
this design/parameter attack.

The closest prior art is nevertheless explicit:

* CEDRUS-alpha Section 3.2, Equations (3.1)--(3.2), mixes over how often a
  given FORC instance is hit and gives an approximate `p_FTS_Succ(q)` and
  `pSucc(q_sig)`. It already describes the generic accumulation mechanism.
  Its displayed quantity is the success probability of one fresh target; it
  has no `q_H` variable and does not optimize the public target grind.
* Mehdi Abri and Jonathan Katz, *Shorter Hash-Based Signatures Using Forced
  Pruning*, ePrint 2025/2069, pp. 12--13, Equation (2), gives the same
  binomial instance-occupancy structure and explicitly states overall forgery
  probability `q_(H,2) * pSucc(q_S)`. This is direct prior art for offline
  public-hash amplification.
* The CEDRUS framework paper, ePrint 2025/2236, Sections 5.2 and R.3, retains
  the FORC coverage relation and its ITSR security experiment. The broader
  SPHINCS/FORS/FORC literature already treats multi-instance few-time-key
  degradation.

Accordingly, no disclosure should claim a new generic attack family. The
narrow candidate-specific result is the exact NGCC-parameter forgery and the
missing lifetime-policy consequence.

## Resolution of the fourteen frozen objections

1. **Internal PDF inconsistencies:** resolved explicitly above. The coherent
   counter-free parser matches Algorithms 20--21, sizes, and source behavior;
   a public unconditioned counter does not stop the attack.
2. **Possible forced-pruning conditioning:** no such loop or predicate is
   specified or implemented. Uniform ideal digest chunks are the correct
   ordinary-signing model.
3. **Full address:** passed. Collection keys on both `idxTree` and `idxLeaf`
   under the PDF-width address. Wrong-component controls reject.
4. **Direction/endpoints:** passed. Only `ell_donor<=ell_target` and public
   forward steps are used under the operational Algorithms 14--18 convention.
5. **Authentication paths:** passed. Every copied path stays with its own
   coordinate and leaf. Tampered and cross-address controls reject.
6. **Fixed suffix:** passed. Mixed components reconstruct the fixed
   `PK_FORC(A)`; the bottom WOTS/XMSS address remains `A` and a wrong suffix
   rejects.
7. **Address event:** passed. It is included in the realized table mass
   `2^-h sum_A Z_A`; the fixed-address check pays `2^h` in both collection and
   target search.
8. **Fresh ordinary hedging:** passed. Acquisition uses independent fresh
   signer randomness; only the forgery-stage public `R` is attacker-selected.
   The target message was never queried.
9. **High-confidence probability:** passed. Exact second moments,
   Chebyshev, fixed target counts, and a hard signing-query abort replace an
   expectation-only claim. Fixed-address analysis uses Chernoff and
   Paley--Zygmund.
10. **Headline complexity:** objection sustained as a qualification. The
    `2^71` figure counts interactions, while traffic and signer work are near
    `2^88`--`2^89` at the relevant points.
11. **Memory:** passed with qualification. The six-bit shard's complete
    full-path payload has a deterministic `2^79.175`-byte capacity. It does
    not replay randomized queries or depend on frontier compression.
12. **Implementation artifacts:** passed. The independent model uses full
    addresses and correct hash domains; all known code deviations are
    unnecessary and excluded.
13. **Lifetime versus evaluation:** passed. No candidate cap was found;
    `2^64` is the official minimum support requirement, while `2^80` is the
    evaluation query ceiling. The attack uses more than `2^64` but less than
    `2^80` signing queries.
14. **Novelty:** objection sustained. Generic accumulation and `q_H`
    amplification are prior art. Novelty must be limited to the concrete
    CEDRUS-alpha parameter/lifetime conclusion.

## Reproduction and limits

From the extracted reproducer root, run:

```sh
./run.sh
```

`scripts/hostile_complexity.py` uses only the Python standard library and
records all model values in `work/hostile_complexity.json`.
`scripts/toy_spec_verifier.py` records the
end-to-end reduced forgery and controls in `toy_spec_results.json`.
`scripts/validate_release.py` checks the verdict-critical invariants.
`IMMUTABLE.SHA256SUMS` seals the replay inputs.

The result is mathematical and end-to-end at reduced dimensions. No claim is
made that the full resources were instantiated, that it runs on the present
machine, or that the generic attack family is new. Those limitations narrow
the presentation; they do not invalidate the specification-level
chosen-message forgery under the submitted uncapped key policy.
