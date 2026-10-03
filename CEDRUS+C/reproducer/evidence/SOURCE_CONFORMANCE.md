# Strict repaired-verifier trace

The strict repaired-verifier analysis uses the submitted 160s source after a
scheme-favourable specification repair. The exact diff and verifier core are
included in the release:

```text
patches/spec-repair.patch
SHA-256 4a4fd267abd341149abae1662c24a09018f0159cd168209556652d24839e6f41
```

The patch was applied before the strict repaired-verifier tests.  It repairs
the
Table 1.2 compressed address, the bottom-tree bit split and full tree-index
decode, counter-zero handling, counter placement in serialized WOTS records,
WOTS digit extraction after the leading-zero prefix, and the signer-side
fixed-sum predicate.  `patches/verify_core.c` adds the strongest coherent
verifier interpretation rather than relying on the submitted verifier's
omitted WOTS membership check.

The relevant strict repaired-verifier flow is:

1. Require the exact `SPX_BYTES` signature length.
2. Read serialized `ctrFTS`; recompute HMSG from serialized `R`, the public
   key, message, and counter; reject unless the forced field is zero.
3. Decode the full bottom `tree` and `idx_leaf`; install both in the layer-zero
   WOTS/FORS address.
4. Reconstruct the FORS public key from the `k` serialized components in their
   fixed coordinate order.
5. At every hypertree layer, read the serialized WOTS counter, install it in a
   `COMPRESS_WOTS`/ROOT_HASH address carrying that exact layer, tree, and
   keypair, recompute HRoot, and require `wots_digest_valid`.
6. Reconstruct the WOTS key, WOTS leaf, and XMSS root; update the next-layer
   leaf and tree by the exact per-layer height; finally compare the top root.

This flow is visible in the pinned `patches/verify_core.c`.  The
serialized public target freedom is visible at lines 138--150 of the repaired
`hash_sm3.c`: verification accepts the provided counter (including zero) and
has no PRFMSG-origin test for `R`.  The HMSG layout consumes a byte-rounded
forced field, then disjoint FORS-message, tree, and leaf fields.  The repaired
tree field uses `SPX_FULL_HEIGHT-SPX_BOTTOM_TREE_HEIGHT`, so `(tree,leaf)` is a
bijection over all `2^h` complete bottom addresses.

The strict repaired-verifier acceptance argument for the accumulation forgery
does not depend on the looser `cedrus_c_verify_coherent` entry point.  Every mixed FORS
coordinate reconstructs the same fixed per-coordinate root at the same
complete address, hence the same fixed `P_A`.  The copied bottom WOTS signature
therefore authenticates exactly its original message.  All upper messages and
suffix records are copied unchanged.  Every strict repaired-verifier
membership test sees the same message, address, counter, and legal digest as
in the donor signature.

Two kinds of experiment are kept separate:

- `native_fors_splice_160f` and `native_fors_splice_160s` exercise the full
  submitted FORS dimensions and native hash/address code.  They validate the
  coordinate splice and its address/order/tamper controls, not the infeasible
  acquisition phase or a full strict repaired-verifier transcript.
- `toy_strict_forge.py` exercises ordinary randomized acquisition, public-R
  target grinding, strict repaired-verifier WOTS membership, a full XMSS
  suffix, fresh-message acceptance, and seven negative controls at scaled
  dimensions.

No test result is presented as a physically obtained submitted-dimension full
forgery.  The actual collision/coverage acquisition is quantified in
`HOSTILE_AUDIT.md` and is far beyond this host.
