# MORNING-ATLAS-128 key-4 public outcome before calibration

This record was written after the prospectively frozen public attack finished
and before either ground-truth `s1` or `t0` was generated for key identifier 4.

## Freeze

- Protocol: `MORNING_ATLAS_KEY4_PROSPECTIVE_PROTOCOL_2026-09-27.md`
- Freeze-manifest SHA-256:
  `9bebb94f64c14906f1284b25293a32d65bb86504c8bc96f95300330b0545a18c`
- No recovery code or parameter was changed after the freeze.

## Public transcripts

- Corrected-sampler signatures: 3,000,000 distinct chosen messages
- Retained response-support rows: 1,931,974
- Four-core collection wall time, summing the longest shard in each sequential
  batch: 5,064.681 seconds
- Response transcript SHA-256:
  `355829fab9c9b869fa0d28eebd0e93258d276f5be69149228aeeecbaf9e7bec4`
- Hint records: 20,000, drawn from the first 20,000 chosen messages
- Hint transcript SHA-256:
  `e9648f88bffb2e1e9873a7b649b7fcdd5f20f863f295adbe8af7318b0ce818da`
- The public keys embedded in the response and hint transcripts matched byte
  for byte.

## Public recovery and validation

- Every rounded minimax `t0` polynomial had zero public hint-bound violations.
- Recovered `t0` text SHA-256:
  `5c4b519e5094a65b8216abd1c5ad628fa4c04421f6d24c20d6524c6c1e05ed5f`
- Public full-`t` LWR instance SHA-256:
  `48771ce7745edc7181141dd0ac33d00f92372e969b36c9889bc35ed7b3917802`
- Radial output SHA-256:
  `bec72132640aa1d8d1a3666a33367580fb4c958f9c065edc5ad7f13843bcc630`
- The six response-only integer blocks had zero full-response violations.
- The assembled integer baseline already passed all 1,152 LWR checks with
  residual range `[-16,15]`.
- Integer baseline SHA-256:
  `a5fae301bdafabdd6858e99c61686cfb02478e0b2f096a4d1489157a354debbe`
- The frozen lattice ladder was still run exactly as prescribed.  It succeeded
  for block 0 after BKZ-10, passed every public check, and returned the exact
  same 768 coefficients as the integer baseline.
- Lattice output SHA-256:
  `e006ad71b4ab591b3f723173aaaf8fbf77454761d4ae2785a62730349240c4a9`
- Recovered `s1` text SHA-256:
  `c5111d7b13af090288d583081f1f493747bd28283042069e9d40ccffe8c73375`

## Equivalent-key result

- The recovered `(s1,t0)` and public key formed an equivalent signing key.
- The faithful signer produced a 2,081-byte signature on the preselected
  80-byte fresh message, and the original public-key verifier accepted it.
- Fresh-message SHA-256:
  `f8c2176013c95828924047eafdc857ee9a03378939cedd5b7c9a42ac23035a07`
- Detached-signature SHA-256:
  `b4a98b0913b409c8ded21762cf0bd69b4d08aef19fba4e7f2c4c85a6869da2bb`
- Equivalent-key SHA-256:
  `32130947f97b0982c4e89124b7f0f076f926042810f9e35bc579d610469f49d9`

The prospectively frozen public procedure therefore succeeded end to end on
the independent key before any comparison with its generated secret.
