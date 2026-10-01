# Galas pristine-source validation report

Date: 2026-10-01 (UTC)

## Verdict

The requested validation passed at all four submitted field sizes.

1. At 160, 256, 384, and 512 bits, one S signature and one F signature
   produced by the untouched submitted interfaces on the same message under
   byte-identical underlying key material recovered the exact normative key
   `k`.
2. At each size, the recovered `k` was converted only into the submitted
   wrapper's documented cache format `x || k`, passed to the untouched
   submitted F signer on a fresh message, and the resulting signature was
   accepted by the untouched submitted F verifier.
3. For all eight S/F profiles, the untouched submitted signer and the repaired
   specification oracle produced byte-identical complete serialized
   signatures for matched key and message inputs.
4. Wrong-message, wrong-public-key, and wrong-secret controls rejected at
   every size.

This experiment validates the implementation-independence of the attack
mechanism. Its prerequisite remains one same-key, same-message S/F signature
pair at a fixed field size. It does not establish an isolated single-variant
EUF-CMA break.

## Pristine source identity

The reference source was extracted afresh, without edits, from:

```text
98d57af868fa10d74b2c0656e565aa14a42ff902646d6fc440ffb7355b75342c  sign-12.zip
```

`PRISTINE_SOURCE.SHA256SUMS` covers all 552 files below the archive's
`Implementations/Reference_Implementation` directory. It was checked before
and after all builds and experiments; both checks passed for all 552 files.
Build products were written only to `build/` and experiment products only to
`out/`; the extracted source tree stayed unchanged. In particular, the
submitted combined sign/verify implementation has hash:

```text
ab53ba0a3d7c0fa296b46fdceacd6fefb39cd0c701ac9b137ce167a65f1eb3df  ngcc/SIG_AlgorithmInstance.c
```

That file is byte-identical in all eight submitted reference-profile
directories. The complete compiler commands are in `build.log`. The build
used GCC-compatible `cc` 13.3.0 with the submission's reference flags:

```text
-std=c99 -Wall -Wextra -Wpedantic -O2 -D_POSIX_C_SOURCE=200809L
```

`pristine_cli.c` is a file-I/O harness. Its `verify` operation calls the
submitted `sig_verify` directly. Its ordinary `keygen` and `sign` operations
likewise call `sig_keygen` and `sig_sign` directly. For signing after key
recovery, `sign-norm` performs only the necessary interface conversion from
the PDF key `k` to the source wrapper's cached `x || k` representation, taking
`x` from the first half of `pk`; it then calls the untouched `sig_sign`.

## Whole-transcript equivalence for all eight profiles

For each field size, the submitted S and F key generators were given the same
explicit KAT seed. They produced byte-identical `pk` and cached `x || k`
values. The repaired oracle generated the same `pk`; its normative `k` was
byte-identical to the second half of the submitted cached secret, while the
first half of that cache was byte-identical to the public `x`.

The submitted signer is deterministic. For fixed key and message, there is no
additional external signer-randomness input to match: `mu`, `rootKey`,
`iv_pre`, `iv`, the commitment state, all Fiat-Shamir challenges, the opening,
and the grinding counter are fixed. The test therefore supplied the same
`(pk,k,message)` through the two key-interface encodings and compared the
entire serialized signature with `cmp`.

| Profile | Signature bytes | Submitted signature SHA-256 | Repaired signature SHA-256 | Exact equality |
|---|---:|---|---|---:|
| Galas-160S | 4,812 | `9859a1242bb7d7b5755452295d0bb7a4da8546306a9eddae62c1d4c539d39230` | same | yes |
| Galas-160F | 5,964 | `0cacfff1200e847e9a9bc8239b7899cbe10f67ef0f9e00b151cd1f5d7784914d` | same | yes |
| Galas-256S | 12,114 | `7d73c06255b34650ecc2bc474236f27d98975f6259ecc5e8e7c1408dec4358ea` | same | yes |
| Galas-256F | 15,950 | `d30ee52a8b2276df23930e0e6fb917302304d16c60bd6be3b9dd6c5c5e3087d9` | same | yes |
| Galas-384S | 27,784 | `166e2bc1bc1cdc8657b24e34178032af8bbf32a48ab383075a3fc6dad39b9279` | same | yes |
| Galas-384F | 33,384 | `c27ae298c8b8eecde60d0f29ffb096ef4643f82abd6c3b5e84cf771cd567bce6` | same | yes |
| Galas-512S | 49,516 | `fda7ff0f8f5cf607cbdd1840a7c03ef0c8f2fe27d53078dcd6454750b4dc641e` | same | yes |
| Galas-512F | 59,416 | `2d5115b086ec3c26b347cf5d8f1505e79cbda2da838e4461e406d660a14e64f2` | same | yes |

For each profile, the untouched verifier accepted both the submitted-source
transcript and the repaired-oracle transcript. The repaired verifier also
accepted the submitted-source transcript. Thus the comparison is full
serialized-transcript equivalence, rather than equality of a selected core
field.

The repaired source differs from the submitted source only in the documented
interface repairs and portability cleanup: normative `sk=k` metadata and API,
full host-size message lengths, and a defined zero-count 32-bit rotation in
the supplied SM3 code. The exact eight-profile equality above shows that none
of those repairs changed the tested transcripts on this platform. The
repaired inputs used here are identified by
`REPAIRED_ORACLE_INPUTS.SHA256SUMS`.

## End-to-end attack through submitted interfaces

At each size the attack program received only `sig-pristine-s.bin` and
`sig-pristine-f.bin`, both emitted by the original submitted S/F APIs. It did
not receive the public key, original cached secret, or normative key. It
reconstructed the missing F tree-0 seed from the S opening, computed `u_F`,
and wrote the first `lambda` bits of `d_F xor u_F`.

| Level | Recovered/original key SHA-256 | Recovery time | Recovery peak RSS | Fresh F forgery SHA-256 | Untouched F verify |
|---:|---|---:|---:|---|---:|
| 160 | `01f62f9bd378ef93973c4c172ba0b804377b165244c4eb6d66319ac24e50bb76` | 0.05 s | 2,048 KiB | `3de6b380fa1b66f3b8e9c6f7afb68e735affdacc6bd8fc1fc087aed75fcbf952` | accept |
| 256 | `f6cfa8d2893aa50a1209aa26f9f50fa84a8a604f8b34e1bf0d2df513af6af6b8` | 0.25 s | 6,144 KiB | `5c6dac5a3b97a936e620e914c78a82f0baf73ac03eb4eebf42b8ce3dc3952cfe` | accept |
| 384 | `4912dc210cbea31f3bfb92b836098bcf8a1743f462efbbb0fb8cea9a5070deb8` | 0.60 s | 13,312 KiB | `c948fb6bf8174982b1b7fe18ba4f84c5510abb2ce7ab4dd20b946b6e3e569970` | accept |
| 512 | `030a6600d808826e82413536470d3c4307f2bb39e09e25b3622ad82cbc4973aa` | 1.19 s | 24,576 KiB | `c46bd1ab27c09016c219c0b6b7a012e0ca1d59cee8eeb35366cff584767d2875` | accept |

Every recovered key matched both (a) the normative `k` suffix of the untouched
wrapper secret and (b) the repaired oracle's Algorithm-19 key byte for byte.
At 160 bits an additional F-only control stopped at the single hidden tree-0
leaf (`rc=5`); adding the S transcript supplied that node and recovery
succeeded.

The fresh-message signatures were generated after recovery through the
untouched F `sig_sign` and accepted through the untouched F `sig_verify`.
Verifier timings were 0.77, 3.12, 11.06, and 33.25 seconds respectively. The
512-bit signer used about 80 MiB for the F profile; the attack itself used
24 MiB.

## Negative controls

The following controls were run independently at 160, 256, 384, and 512 bits,
all through the untouched submitted F verifier:

- the fresh forgery was tested against a different message and rejected;
- the original chosen-message F signature was tested against the fresh
  message and rejected;
- the fresh forgery was tested against an independently generated public key
  and rejected; and
- an F signature made with an independently generated wrong `k` but the
  target public `x` was tested under the target public key and rejected.

Each verifier rejection returned the submitted implementation's final
Fiat-Shamir mismatch code (`-8`, mapped by the harness to process status 4).
These controls exclude accidental message acceptance, accidental public-key
acceptance, and a forgery path that does not depend on exact key recovery.

## Reproduction and retained evidence

From this directory, the exact build and validation entry points are:

```sh
make -j16 all 2>&1 | tee build.log
./run_validation.sh
```

The validation run started at `2026-10-01T08:47:29Z` and completed at
`2026-10-01T08:58:20Z`; the four levels were run concurrently. Exact commands,
seeds, command outputs, per-command elapsed/user/system time, peak RSS, return
codes, comparisons, and controls are retained in `out/final/validation.log`
and the per-level `out/final/<level>/run.log` files. Per-level binary artifact
digests are in `ARTIFACTS.sha256` in each level directory.

The experiment intentionally leaves the authoritative archive and the release
paper/package untouched. `SHA256SUMS` identifies the report, harness, scripts,
logs, manifests, binaries, and generated evidence in this validation tree.
