# TRINE short-seed collision reproducer for the unsalted specification

This bundle reproduces the candidate-specific application of the known
short-seed collision attack to the direct unsalted construction described in
the TRINE specification.
It covers both level-I profiles:

- Balanced-I: one cross-label collision recovers an equivalent signing
  witness;
- ShortSig-I: a connected five-label collision graph recovers all maps.

The full target attack cannot be run on this machine.  A main fixed-index point
uses exactly `Q = 2^64 - 1 = 18,446,744,073,709,551,615` ordinary signing
queries.  The exact ideal model reaches approximately 50% success with
`2^64.879318`/`2^67.639106` public seeds and the same number of 256-bit
canonical hashes.  Returned traffic is `2^78.609179`/`2^77.661778` bits; raw
48-byte seed/hash tables occupy `2^70.464281`/`2^73.224068` bytes; measured
attacker work is `2^94.246627`/`2^96.990188` cycles; and honest signer work is
`2^97.268224`/`2^96.182868` cycles.  The submission specifies no per-key
lifetime cap that excludes this point.  These are full-parameter attack bounds,
not a physically executed full-entropy attack.  This is not a physical `2^80` attack.

The executable experiments retain the exact field and level-I dimensions and
reduce only round-seed entropy from 128 to six or eight bits. Signatures use
fresh independent DRBG output. No reset, rollback, fault, repeated-state
control, related key, or rare key is used.

A separate conformance target uses the minimally specification-aligned source
at the real 128-bit round-seed width.  It generates and verifies one ordinary Balanced-I
signature of exactly 3,124 bytes and one ShortSig-I signature of exactly 1,620
bytes.  It performs no collision or forgery.  Only the reduced-seed runs make
the birthday events reachable and execute the full extraction-to-forgery
chain.

## Scope

The claim is limited to the direct unsalted, message-independent decoder
described in the specification.
The untouched salted source serializes a fresh 32-byte level-I salt and is not
vulnerable to this accumulation mechanism.  This is not an implementation
break. See `SOURCE_SCOPE.md` and the two patches under `patches/`.

## Requirements

- GCC or Clang with GNU11 support;
- GNU Make;
- Python 3;
- OpenSSL development headers and `libcrypto`/`libssl`;
- GNU `time` and `sha256sum`.

## Reproduce

```sh
./run_all.sh
```

The Balanced and ShortSig full-dimension reduced-seed runs execute in
parallel. On the audit host, the slower frozen run took about eight minutes and
used about 72 MiB peak RSS. A successful run ends with:

```text
validation=PASS
```

To validate the frozen outputs and checksum manifest without rerunning the
experiments:

```sh
./run_all.sh --validate-only
```

Fresh outputs are written below `results/latest/`, which is intentionally
excluded from `SHA256SUMS`. Frozen evidence is under `results/frozen/`.
The release ZIP itself is created with normalized timestamps, file modes, and
sorted entries by `scripts/make_release_zip.py`.

## Prior art and claimed contribution

Ward Beullens, “Trivial multi-key attacks + attack on ALTEQ,” NIST PQC Forum, 21 February 2024, describes the public-table short-seed attack and the
seed/salt/round repair:

<https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/tjhrrmv837w/m/sjxHooYgBAAJ>

Arnaud Sipasseuth, *DVA: Dangerous Variations of ALTEQ*, IACR ePrint 2024/817,
Section 3.2, explicitly includes internal collisions and the salted repair:

<https://eprint.iacr.org/2024/817>

The generic mechanism and repair are prior art. The claimed contribution is
limited to the TRINE construction described in the specification, its
specification/source salt discrepancy, canonical-certificate extraction,
Balanced one-edge and ShortSig connected-graph completion, exact level-I costs,
and full-dimension reduced-seed fresh-forgery validation.
