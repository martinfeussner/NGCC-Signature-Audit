# MORNING-ATLAS-128 first-gate recovery reproducer

This is the frozen public pipeline described in the paper. It tests the written
ATLAS-128 design with faithful uniform samplers, separate from the already
published repeated-mask and decoder faults in the submitted implementation.
The recovery consumes public signature fields and a public key. It recovers
`s1`, recovers the omitted `t0` from public hints, constructs an equivalent
signing key with a fresh seed, and requires a fresh-message signature to pass
the verifier.

Two keys were tested with three million signatures each. The second key was
selected only after the code, parameters, block order, and stopping rules had
been frozen. Both succeeded, but two trials do not estimate a key-averaged
success probability.

## Fast evidence replay

The small `evidence/` directory contains the prospectively tested key's public
key, recovered components, equivalent key, message, and signature. No original
secret key is included. Build the faithful implementation, verify the saved
forgery and changed-message control, then reconstruct the equivalent key and
signature with:

```sh
./verify_evidence.sh
```

## Full public recovery

Requirements are Bash, GNU Make, a C compiler, Python 3, NumPy, SciPy with
HiGHS/MILP support, and fpylll 0.6.4. The main prospective experiment is:

```sh
PYTHON=/path/to/python-with-dependencies ./run_full.sh 3000000 4 4
```

The command generates twelve disjoint 250,000-signature shards in batches of
four, merges roughly 1.93 million retained public inequalities, generates the
20,000-record public-hint transcript on the same first 20,000 messages, and
runs the fixed recovery stages. It ends only after full response and LWR
validation and a verifier-accepted fresh-message forgery.

The reported prospective run took about 84 minutes for four-core collection
and about 12.5 minutes for public recovery on an Intel Core i5-6500. Peak
recovery memory was about 1.42 GiB. Generated transcripts occupy hundreds of
megabytes and remain under `build/`, which Git ignores.

The protocol frozen before the second key and the record written before its
secret was revealed are included as
[`MORNING_ATLAS_KEY4_PROSPECTIVE_PROTOCOL_2026-09-27.md`](MORNING_ATLAS_KEY4_PROSPECTIVE_PROTOCOL_2026-09-27.md)
and
[`MORNING_ATLAS_KEY4_PUBLIC_OUTCOME_BEFORE_CALIBRATION_2026-09-27.md`](MORNING_ATLAS_KEY4_PUBLIC_OUTCOME_BEFORE_CALIBRATION_2026-09-27.md).
