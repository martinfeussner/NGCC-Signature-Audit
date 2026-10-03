# Specification and source boundary

The attack in this bundle targets the direct unsalted, message-independent PDF
realization of TRINE. Algorithms 6--8 first sample each round point, then hash
the message, and Section 3.5 counts exactly `lambda` bits for every base-opening
seed. The algorithms and size formula contain no per-signature salt.

The complete decoder evidence is cumulative: Algorithm 6 samples points before
the message hash; `Corank1Cal(phi_X)` has no message argument; Section 3.4
permits seed compression; Section 3.5 allocates exactly `lambda` bits per base
seed; and Algorithms 6--8 plus the size formula contain no salt.  The PDF sizes
are 3,124 and 1,620 bytes for the level-I profiles.

The submitted source defines a different round domain:

```text
"MEDS2END-TRINE-ROUND-v1" || salt || round_seed || LE32(round_index)
```

It serializes a fresh `2*lambda`-bit salt, making level-I signatures 32 bytes
longer than the PDF sizes. Independent salts block cross-signature seed
accumulation. The attack does not apply to the untouched submitted source.
That source is not vulnerable to this accumulation mechanism, and the report
does not claim an implementation break.

`patches/remove-source-only-salt.patch` is the minimal PDF-alignment patch. It
removes the salt from sampling, serialization, codecs, and the XOF input while
preserving the domain string, round index, SHAKE256, field sampler,
`Corank1Cal` retry path, canonicalizer, challenge parser, and verifier.

`patches/native_spec_and_instrumentation.patch` records the additional
test-only changes: six-bit seed domains, export of the public canonicalization
certificate, omission of the salt from the serialized PDF transcript, and use
of a fixed public all-zero value at the former internal salt input. A fixed
public value adds no per-signature entropy, so this instrumented source has the
same cross-signature decoder behavior as the direct unsalted construction.
The minimal patch above is the exact remove-the-salt conformance path; the
source in `src/native/` is the separately instrumented hostile-test oracle.

The source under `src/pdf_full_entropy/` is a clean reference-source copy with
only the minimal PDF-alignment changes.  Its round seeds remain 128 bits.  The
`full_entropy_balanced` and `full_entropy_shortsig` targets generate and verify
one ordinary signature at the exact PDF sizes.  They are conformance tests, not
collision or forgery experiments.

The PDF never spells out the seed decoder. An unstated decoder
`D_i(seed,message)` would defeat accumulation. It is neither the displayed
sampling order nor the submitted decoder. This ambiguity is why every claim is
limited to the direct unsalted, message-independent PDF realization.
