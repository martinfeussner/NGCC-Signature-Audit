# Specification-conformant Galas oracle

The submitted Galas wrapper has unrelated implementation deviations, so this release tests the
attack through `oracle/ngcc/SIG_SpecOracle.c`, an audit entry point for the normative PDF
algorithms.

## Repairs used by the experiment

- `spec_sig_keygen_seeded` implements Algorithm 19 and emits `pk=x||y`, `sk=k`. Its explicit
  seed is mandatory, eliminating the submitted wrapper's public all-zero fallback.
- `spec_sig_sign` implements Algorithm 21 with the normative `(pk,sk,M)` input. The source
  wrapper instead caches `x` inside `sk=x||k` because its API omits `pk` from signing.
- `spec_sig_verify` implements Algorithm 22.
- `galas_hash_mu` and the specification entry points pass the complete host-size message length,
  avoiding the submitted wrapper's 32-bit truncation.
- The packaged `auxfunc.c` and `drng.c` use a defined `uint32_t` rotate for a zero rotation
  count. The submitted SM3 macro otherwise evaluates a right shift by 32 at rounds 0 and 32,
  which C leaves undefined. This portability cleanup does not change fixed-seed transcripts;
  the complete 160-bit attack and controls pass ASan/UBSan in
  `evidence/postfix-sanitizer.log`.
- The packaged instance metadata records the normative secret-key sizes (`lambda/8`) rather
  than the unused source-wrapper `x||k` cache sizes.

The cryptographic core, BAVC layout, GGM/VOLE expansion, challenges, proof, and verifier checks
are the submitted Galas algorithms. The official archive itself was preserved unchanged during
the audit.

## Conformance evidence

Before release, separate controls built the submitted wrapper and this
specification oracle from a fresh extraction of the official archive. For the
same explicit seed and ordinary `(pk,k,M)` values they established:

- the normative `k` is exactly the suffix of the source wrapper's cached
  `x||k`, while the prefix is the public `x`;
- the submitted and normative signers emit byte-identical complete serialized
  signatures for all eight Galas S/F profiles; and
- each submitted verifier accepts both transcripts, while each normative
  verifier accepts the submitted transcript.

At 160, 256, 384, and 512 bits, the attack program then received only the S and
F signatures emitted through the original submitted interfaces. It recovered
the exact normative key, which was converted only to the wrapper's documented
`x||k` cache format and passed to untouched `sig_sign` on a fresh message. The
resulting signature was accepted by untouched `sig_verify` at every level.

The independent hostile review repeated the original Galas-160 comparison from
a clean extraction. The later all-profile validation and its controls are in
`evidence/pristine-validation/`. `run.sh` remains the compact normative replay;
the pristine validation directly tests that the result does not depend on these
wrapper repairs.

Source identities (the first two authoritative inputs are not bundled; the third is included):

```text
95d66ea845f96eadd68900db95a0554a6b106dce4c26d972aab33f5eb09c7c19  sign-12-spec.pdf
98d57af868fa10d74b2c0656e565aa14a42ff902646d6fc440ffb7355b75342c  sign-12.zip
374c4729cbfd7c74b5b8f37baecd9b5473af82e642e23682ea5197b0c10e1b45  oracle/ngcc/SIG_SpecOracle.c
d96673bab53e9a3cee0dd5f21ad58ac5c8721fd73e7a18b568fbb18b60cb39e7  oracle/ngcc/auxfunc.c
10ccd22c1d503d29cd7b0654c040eb49dcd46e479d11fb1bc3a735b92adf4bde  oracle/ngcc/drng.c
12b9658ce0346e47c3f01490a4a5499b5f37b3eb1e780ee482c1ebe6c1f2c3fa  oracle/galas/instances.c
54ccc025457c1d4eae9c32d668ba5655ddd03255e712300d7265a1cd98d1ddc1  oracle/galas/instances.h
```
