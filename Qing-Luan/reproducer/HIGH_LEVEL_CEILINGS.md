# Separate review of the 384/512 state ceilings

These observations are independent of the practical rollback extractor and do
not make that attack stronger.

## Specified / standalone Hash-DRBG

PDF section 1.5.4 specifies a 32-byte SM3 Hash-DRBG seed/state root.  The normal
reference implementation in `src/utils.c` stores 32-byte `V` and `C`; after
initialization `V` is one SM3 digest and `C` is a deterministic function of
`V`.  Its counter starts at a fixed value.  Consequently, a complete output
schedule is selected from at most `2^256` initial states even when callers ask
for 384-, 768-, or 1024-bit strings.

Thus the nominal 384/512 key distributions and signing-randomness pairs in the
written/standalone construction have support at most `2^256`.  Generic
single-target enumeration is bounded by `2^256` classical work (about `2^128`
ideal Grover work).  This is infeasible on the audit machine and is a claimed
security ceiling, not a practical recovered-key result.

The submitted API_PKC KAT adapter is a different DRNG implementation with a
55-byte internal `V`; the exact 256-bit standalone bound should not be
attributed to that adapter.  The practical rollback attack was reproduced with
both backends and does not rely on either state width.

## QingLuan-512 counter-XOF

The squeeze rule is `O_i=SM3(K || BE32(i))`.  At level 512, `K` is exactly 128
bytes, or two complete SM3 blocks.  After those blocks are processed, every
output block is determined by one 256-bit chaining state plus the known fixed
length and counter.  Enumerating that state against the public `Seed_pk` blocks
recovers the preceding hidden `Seed_e` blocks in at most `2^256` classical or
about `2^128` ideal quantum work.

`xof512_state_check.py` independently implements the SM3 compression function.
It takes an arbitrary 128-byte key, computes the state after the two complete
key blocks, and reconstructs eight consecutive squeeze blocks.  All 256 bytes
match direct OpenSSL/Python SM3 evaluation.

At level 384 the 96-byte key is not block-aligned: 32 key bytes remain after
the first full block and share the next compression block with the public
counter.  The same simple one-state `2^256` argument therefore does not apply;
the separately specified 256-bit DRBG support ceiling still does.

## Verdict

* `384/512 specified standalone DRBG support <= 2^256`: mathematically valid,
  impractical generic ceiling.
* `512 counter-XOF stream determined by a 256-bit post-key state`: valid and
  independently reproduced, impractical generic ceiling.
* `384 counter-XOF has the same one-state ceiling`: rejected.
* Either ceiling is the cause of the practical rollback extraction: rejected.

