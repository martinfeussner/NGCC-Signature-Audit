# Specification conformance

The mathematical attack follows the submitted CEDRUS-alpha PDF rather than the
known divergent source behavior. The coherent interpretation used by the
reproducer is:

1. Algorithms 20 and 21 are counter-free. The exact `ctrFTS` token occurs only
   in Algorithm 20, line 16. Equation (1.3), Figure 1.14, and the `HMSG` rows of
   Tables 1.2--1.3 retain related dangling counter notation, but no generation
   loop, predicate, verifier check, or distribution exists. Algorithm 20 line 4
   and Algorithm 21 line 7 call `HMSG` without a counter; Algorithm 21's parser
   and length equation, Table 1.1, and Equation (4.1) are counter-free. All 16
   source trees agree. Retaining an unconstrained public counter would only give
   the attacker another public target-search input.
2. The stale `FORS` and `PORS` names in Algorithms 20 and 21 mean the FORC
   algorithms defined in Section 1.9.
3. The digest parser includes the `k log2(W)` chain-position bits, as specified
   by the later complete formula and Algorithms 16--21.
4. Chain positions are `0,...,W-1`, and the authenticated endpoint is `C(W)`,
   following Algorithms 14--18. If the prose-shifted `C(W-1)` endpoint is used
   instead, the coverage condition remains exactly
   `ell_donor <= ell_target`; the first and second moments are unchanged.

The bundled 256f reference source contains only the repairs recorded in
`SPEC_REPAIRS.patch`: full-width address fields, the PDF's Table 1.2 PRF/hash
input organization, and full constant-sum WOTS message handling. The native
check establishes honest hedged signing and verification, exact submitted
signature size, message/`R`/FORC/WOTS mutation rejection, wrong-key and length
rejection, full-width chain addressing, the Table 1.2 PRF vector, and full WOTS
message use.

`vendor/submitted-pristine-256f/` contains the byte-exact submitted source
files needed for the replay, including their CRLF endings and the missing
terminal newline in `thash_sm3_simple.c`. Run
`python3 scripts/replay_spec_repairs.py --output build/spec-repair-replay` to
normalize those textual details deterministically, apply `SPEC_REPAIRS.patch`,
and compare every resulting source byte with `vendor/spec-repaired-256f/`.
The top-level `run.sh` performs this check and compiles from the replayed tree.

The reduced verifier is independent code. It implements the complete address,
FORC chain direction, coordinate Merkle paths, fixed address-specific FORC
public key, public serialized `R`, and a reduced Merkle-authenticated hypertree
suffix. SHAKE is used as an ideal-primitive stand-in at reduced dimensions. It
does not emulate any known submitted-code defect.

The separate full-parameter splice check uses the submitted node sizes,
address widths, tree heights, coordinate counts, chain lengths, Algorithm 16
bit ordering, and Algorithms 13--18 address dependencies for all eight sets.
It constructs complete FORC trees at one full address and mixes three valid
donor vectors. SHAKE256 is again a deterministic ideal-primitive stand-in, so
this checks the structural FORC relation rather than the submitted SM3 byte
implementation. The script separately evaluates the Algorithms 14--18
endpoint `C(W)` and the prose-shifted endpoint `C(W-1)`; both accept because
the splice uses only `ell_donor <= ell_target`. It is a full-parameter
FORC-level conformance test, not a full-signature or full-query-budget run.
