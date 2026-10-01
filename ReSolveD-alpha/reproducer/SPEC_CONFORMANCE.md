# Specification conformance notes

## Complete-secret-key CoinHash repair

The ReSolveD-alpha specification defines

```text
sk = seed_pk || seed_sk
(r, iv) = XOF(0x01 || sk || mu || rho; lambda + 120).
```

The submitted reference function `hash_r_iv` absorbs only `seed_sk`. The patch
`full-sk-coinhash.patch` adds `seed_pk` immediately before `seed_sk`, matching
the specified concatenation. No S/F identifier is added. At a fixed security
level, equal full secret keys, messages, and `rho` values still produce equal
`(r, iv)` in S and F, which is the cross-profile condition tested here.

The repair affects only proof generation. Verification reconstructs the
transcript from the signature and never calls CoinHash. Accordingly, final
forgeries are checked by a binary compiled from untouched submitted verifier
source.

## Public-input boundary

`generate_pair` is a deterministic test oracle. It constructs a valid RSD key,
computes the compact honest witness, and produces the requested S/F signatures.
Those secret values are never serialized and are gone when the process exits.

`recover_and_forge` is a separate executable. Its complete input is:

```text
LEVEL PK QUERY_MESSAGE SIG_S SIG_F FRESH_MESSAGE OUT_WITNESS OUT_SIGNATURE
```

It verifies both query signatures, decodes their public challenges, reconstructs
the public portions of each pcGGM opening, and derives an F hidden leaf only
when its parent is reconstructible from the S opening. It checks the recovered
witness against `(seed_pk, y)` before using it. Its proof-generation key is an
attacker-selected auxiliary string used only to select proof coins; verification
does not receive or validate that string.

## QuickSilver specification seam

The PDF's Lemma 3.5 packing formula and some following QuickSilver loop bounds
do not consistently describe the submitted parameter sets. A direct literal
packing check gives out-of-range terms at 160, 256, and 384 bits and omits many
checks at 512 bits. The submitted source hashes the constraint blocks
separately and does not exhibit that literal-PDF issue.

This reproducer follows the submitted source's natural completion for proof
generation and verification. The accepted cross-profile attack does not treat
the malformed formula as a weakened relation: its recovered `W` independently
decodes to a regular error satisfying `H e = y`, and its fresh proof is accepted
by the untouched submitted verifier. The packing seam is therefore outside the
attack claim.

## Excluded integration issues

The package does not rely on uninitialized DRBG state, shared global state,
concurrent API races, signer instrumentation, memory disclosure, or a verifier
implementation bug. The query generator supplies fixed test seeds directly,
and the acceptance oracle is an ordinary submitted verifier build.
