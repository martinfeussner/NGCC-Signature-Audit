# SQIsignTriangle response-rescaling forgery reproducer

This directory reproduces the conditional one-signature fresh-message attack
from the paper against all four submitted SQIsignTriangle parameter sets. For
each trial, the driver creates a fresh key and obtains one genuine signature.
It then gives only the public key, signature, and a distinct target message to
the attack routine. The routine reconstructs the public codomain factors,
selects a factor satisfying the paper's public response-size condition,
chooses a target-compatible response integer, and rescales the serialized
auxiliary basis. It requires the unmodified submitted verifier to accept the
result on the target and reject it on the source.

Requirements are a POSIX shell, Git, GNU Make, GCC, Python 3, and GMP
development headers. Reproduce the paper's three deterministic trials at each
of the 128-, 160-, 256-, and 512-bit parameter sets with:

```sh
./run.sh
```

The script fetches pinned NGCC harness commit
`37ce9750cafd7ea0db0be255e4e8e02f10fe7841`, builds the helper against the
submitted reference implementation, and runs all 12 trials. Set
`NGCC_HARNESS` to an existing checkout of that commit to avoid the clone. Pass
an optional number to change the deterministic key count per level, for
example `./run.sh 1` for a shorter check.

Every successful trial prints its level, key index, response length, selected
codomain factor, forgery time, and `ACCEPT`. The fixed seeds reproduce the
reported eligibility observations; the paper does not claim that a first
response is eligible for every possible key. If neither codomain factor meets
the sufficient condition, the driver stops rather than silently making an
extra signing query.

`recover_codomain.c` performs the public verifier-style isogeny computation
and hashes both recovered factors against the target message.
`forge_and_test.py` performs the response transformation and all four
source/target verification controls. Generated helper binaries are written to
the ignored `build/` directory.
