# Frozen hostile-review model and objections

This file was written before opening any file in
`cedrus-alpha-provable-forgery-20261003/`.  The reconstruction below comes
from the submitted PDF (`sign-04-spec.pdf` / its local `pdftotext` output)
only.

## Reconstructed core

For a bottom-layer address

```
A = (layer = 0, treeAddr = idxTree, keyPairAddr = idxLeaf),
```

FORC consists of `k` binary trees of height `a`.  Tree `i` has chains
indexed by `x in [2^a]`.  Its chain secret is domain separated by the full
address and global chain index `i*2^a+x`.  A digest coordinate is
`(x_i,l_i)`, where `l_i in [w']`.  A signature reveals the chain node after
`l_i` forward hashes and an authentication path for leaf `x_i`.  The
verifier advances it by `w'-l_i` hashes, authenticates that leaf, and
compresses the `k` roots.  Thus a revealed coordinate `(x,l)` can sign
`(x,l*)` iff `l* >= l`; its authentication path can be reused with the
advanced node.  Coordinates from different signatures can be mixed only
when the complete bottom-layer address is identical.  The resulting FORC
public key is fixed for that address, so a whole hypertree suffix from any
valid signature at that address should authenticate the mixed FORC public
key.

For `s` independent signatures at a fixed address, and an independent
uniform target coordinate, the exact ideal-model single-coordinate coverage
is

```
p_s = (1/w') * sum_{l=0}^{w'-1}
      [1-(1-(l+1)/(2^a*w'))^s].
```

Under independent digest segments, all `k` target coordinates are covered
with probability `p_s^k`.  If `Q` signing queries are thrown uniformly into
`2^h` bottom addresses, a random candidate `(R,M,ctr)` succeeds with
conditional probability

```
B / 2^h,  B = sum_A p_{S_A}^k,
```

where `S_A` is the realized occupancy.  Its ensemble mean is
`E[p_S^k]` for `S ~ Bin(Q,2^-h)` (Poisson only as an approximation).  An
expectation over random tables is not itself a per-key success guarantee.

## Objections that must be defeated

1. **Normative algorithm is internally inconsistent.**  The PDF alternates
   FORC/FORS/PORS, includes `ctrFTS` in the serialized signature, gives
   `HMSG` a counter argument, but omits the counter in Algorithms 20--21.
   It also gives inconsistent `m` formulas (with and without the
   `k log2(w')` chain-position bits).  Any repaired semantics must be
   justified from the PDF rather than silently inherited from C code.

2. **Forced-pruning conditioning may invalidate uniform coordinates.**
   `ctrFTS` strongly suggests that the actual digest is selected after a
   rejection/forced-pruning loop.  The joint distribution of FORC
   coordinates, address bits, and counter must be derived.  Treating all
   digest bits as independent uniform bits without accounting for this is
   unacceptable.

3. **Full-address equality is mandatory.**  Equality of only `idxTree`, a
   truncated source address, a FORC chain index, or a key-pair index is not
   sufficient.  The attack must use identical `(idxTree,idxLeaf)` under the
   PDF's full 12-byte tree-address encoding and must not exploit the 22-byte
   SM3 compressed-address instantiation accidentally truncating significant
   bytes.

4. **Chain direction and endpoint convention are ambiguous.**  The prose
   says `w'` nodes including endpoints, while Algorithms 14--18 use positions
   `0..w'` operationally and digest lengths `0..w'-1`.  The attack must use
   only verifier-valid forward moves and explain the off-by-one convention.

5. **Authentication paths cannot be mixed freely.**  Each reused path must
   come from the same FORC coordinate/tree and selected leaf as its chain
   node.  A path from another leaf, coordinate, or full address is invalid.
   A negative control must detect each forbidden mix.

6. **The fixed suffix claim needs exact checking.**  The hypertree suffix
   is reusable only if the mixed FORC components reconstruct exactly the
   address-fixed `pkFORC`, and the bottom WOTS/XMSS address is unchanged.
   No `md`, `R`, counter, or message value may enter `pkFORC` or the suffix
   beyond selecting fixed secret-tree nodes.

7. **Forgery search must include the address event.**  A verifier accepts an
   attacker-chosen serialized `R`, but a random candidate must simultaneously
   hit an exploitable full address and covered FORC coordinates.  A strategy
   that builds a table for one fixed address pays `2^h` both while collecting
   that address and when searching candidates.  An all-address strategy must
   use the realized sum `B`, not substitute a mean occupancy into a nonlinear
   expression.

8. **Freshness and ordinary hedged signing.**  The final message must never
   have been queried.  Collection must use the ordinary hedged signer with
   fresh `addrnd`; no deterministic mode, repeated `R`, state rollback,
   caller-chosen randomness, or related-key condition may be assumed.
   Choosing arbitrary `R` is allowed only at the forgery stage because the
   verifier does not validate its PRF provenance.

9. **Probability needs a high-confidence statement.**  Expected table mass
   or expected work is not a guaranteed attack.  The review needs either an
   exact success probability over key/signer/hash randomness, a proved lower
   bound, or a conservative concentration argument, plus a fixed `Q <= 2^80`
   budget and geometric-search quantiles (not only means).

10. **Complexity accounting may defeat the headline.**  Signature-query
    count, received bits, attacker hash work, table-building work, peak
    memory, and signer hash work must be separate.  For 160f the PDF gives a
    19,420-byte signature, so `2^71.1` queries already transfer about
    `2^88.4` bits before table overhead.  FORC signing and full hypertree
    signing add substantial work.  A `~2^71` oracle-query result is not a
    `~2^71` total-work attack.

11. **Memory cannot be hand-waved.**  Retaining every 160f FORC component
    costs roughly `Q * 4,480` bytes, before addresses and suffixes.  Any
    claimed lower-memory strategy must preserve the rare high-occupancy
    buckets that dominate `E[p_S^k]`, and must state whether it needs replay
    of randomized signing queries.

12. **Source agreement must avoid unrelated source bugs.**  Validation must
    not rely on known WOTS truncation, FORC/address truncation, hash API
    mismatch, or other submitted-code defects.  A separate reduced verifier
    should implement the PDF-level operations and reject wrong address,
    wrong leaf/path, reversed-chain, modified suffix, and fresh random
    component controls.

13. **Key lifetime and evaluation rules are distinct.**  The submitted
    specification must be checked for an explicit per-key signature cap.  In
    parallel, the NGCC evaluation ceiling for chosen-signature work and the
    operational `>=2^64` requirement must be sourced from primary documents;
    an evaluation ceiling is not automatically a recommended operational
    key lifetime.

14. **Novelty must be narrow.**  Multi-target FORS/FORS-like accumulation,
    SPHINCS/FORS few-time degradation, hash-chain directionality, and
    arbitrary-`R` forgery search are generic prior art.  Only a concrete
    CEDRUS-alpha parameter break or a discrepancy in its own concrete
    analysis could plausibly be new.

