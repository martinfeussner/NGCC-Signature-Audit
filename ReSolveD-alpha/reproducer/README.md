# ReSolveD-alpha cross-profile equivalent signing witness recovery reproducer

This package reproduces a practical cross-profile composition attack enabled by
absent cryptographic separation of S/F keys and derivation domains under
same-key reuse in ReSolveD-alpha. At one fixed security level, it takes one
valid S signature and one valid F signature made with the same full secret key
and effective RSD witness material, the same message, and equal
`rho = 0^lambda`. It reconstructs an equivalent RSD signing witness from those
public inputs and uses the witness to create an S signature on a fresh message.

The specification expressly permits deterministic signing by setting
`rho = 0^lambda`. It does not instruct deployments to reuse one key across S
and F. It also does not cryptographically prevent that reuse or separate the S/F
key namespaces. This result is conditional on same-key cross-profile use; it is
not an isolated single-profile, single-oracle EUF-CMA break.

## Requirements

- a POSIX shell;
- a C99 compiler (tested with GCC 13.3.0);
- `patch`, `sha256sum`, and standard POSIX utilities; and
- GNU `/usr/bin/time` for the optional all-level timing run.

The required ReSolveD-alpha reference-source subset is bundled under
`vendor/pristine/`. No network access or external cryptographic library is
required. The default compiler flags target the current host through
`-march=native`; set `CFLAGS` if a different target is needed.

## Minimal replay

From this directory, run:

```sh
./run.sh
```

The last line must be:

```text
minimal_reproducer=pass
```

The command verifies all 80 bundled submitted-source files, builds a signer
with the one conformance repair documented below, and generates deterministic
160S/160F query signatures under one key. A separate process receives only
`(pk, message, signature_S, signature_F)`, reconstructs an equivalent signing
witness, and signs a fresh message. Final acceptance is decided by a verifier
linked only to the untouched bundled submission source.

The replay also checks that:

1. both query signatures verify;
2. their tree salts and IVs agree;
3. the F opening alone keeps every challenged leaf parent hidden;
4. the recovered string satisfies the public regular-syndrome relation;
5. the fresh forgery passes the untouched submitted verifier;
6. that forgery fails under the query and an unrelated message;
7. a one-bit witness mutation yields a rejected proof; and
8. different-message, different-`rho`, and different-key S/F pairings do not
   produce a signing witness.

The test generator retains its deterministic secret only inside the generator
process. The attack process has no secret-key, honest-witness, root-seed, or
signer-state input.

## All recommended levels

To repeat public-input recovery, fresh-message forgery, and untouched-verifier
checks at 160, 256, 384, and 512 bits, run:

```sh
./run_all_levels.sh
```

The final line must be `all_levels_reproducer=pass`. Signing includes challenge
and opening-size grinding, so fixed-input times vary substantially. The log in
`evidence/all-levels-release-check.log` records the release run. Generated
binaries and transcripts are written only to `build/` and `work/`; remove them
with `./clean.sh`.

## Mathematical mechanism

At a fixed level, S and F have the same key format and RSD relation. Neither
`MsgHash` nor `CoinHash` contains the profile identifier. The same full key,
message, and `rho = 0^lambda` therefore give both profiles the same root seed,
salt, and IV.

The F tree is much smaller. Every parent of an F leaf is an internal S-tree
node with the same heap index and seed. An S opening usually permits
reconstruction of at least one such parent. Applying F's public bottom-layer
expansion recovers the missing F leaf seed. The remaining F leaf seeds are
already reconstructible from its opening, so one complete VOLE instance gives
`u_a`. A serialized correction gives `u_0` when `a > 0`, and the serialized
mask then yields

```text
W = d xor u_0[0..ell_wit).
```

Decoding `W` gives a regular error `e` satisfying the public relation `H e = y`.
The attacker does not need to invert the original noise sampler or recover
`seed_sk`: `W` is an equivalent signing witness and a complete signing
capability.

## Source conformity and verifier separation

`vendor/pristine/` is the complete 80-file submitted
`Reference_Implementation/ReSolveD-alpha-160s` directory. Its `instances.c`
contains all eight recommended parameter tables, and the cryptographic core is
identical across the submitted S/F directories. `PRISTINE_SOURCE.SHA256SUMS`
covers every bundled file.

The submitted signer hashes only `seed_sk` where the specification defines the
secret key as `seed_pk || seed_sk`. `full-sk-coinhash.patch` is the sole change
to submitted cryptographic source: it makes CoinHash absorb the complete
specified secret key. It introduces no profile tag. `build.sh` applies this
patch to a temporary copy for query generation and witness-based proof
generation. The separately built `untouched_verify` links directly to
`vendor/pristine` and never to that temporary copy. CoinHash is not evaluated
during verification.

`tools/recover_and_forge.c` independently parses the serialized openings,
reimplements public tree reconstruction, checks the public RSD relation, and
then invokes the specification-repaired prover with the recovered witness and
attacker-selected proof coins. It does not patch or instrument BAVC source.
Further specification details are recorded in `SPEC_CONFORMANCE.md`.

## Submitted-source provenance

The bundled files were extracted from the NGCC `sign-21` candidate archive.
The archive and specification PDF are not duplicated in this reproducer:

```text
499821538d7f79464cc1ee1468254b0e49f750794a591ffe038938c4cfa11914  sign-21.zip
d4433c4960f2d87114b60f61f7781bf718a24c0adfb72c8bc8882f5889aa5b38  sign-21-spec.pdf
e8d45bd69772f8c735a83792f5cf6aeaeedc6565f5d28eec5d949bd9f127bf08  Algorithm specifications Addition.pdf
```

Archive URL:
<https://www.niccs.org.cn/niccs/Proposal/Public-Key%20Cryptographic%20Algorithms/Round%201%20candidates/ReSolveD-alpha.zip>

The submission's source retains its original licensing terms. No broader
license is granted by this package.

## Provenance

The attack, derivation, implementation, experiments, and release package were
produced through an AI-run multi-agent audit by OpenAI Codex using Daybreak Blue
at Ultra reasoning effort. A separately instructed hostile-review agent built
an independent public-input recovery implementation, which is the basis of the
release attack tool. Independent human cryptanalytic review and reproduction
remain pending at the release date.

## Computational resources

The computations were performed on the Norwegian Research and Education Cloud
(NREC), using resources provided by the University of Bergen and the University
of Oslo.
