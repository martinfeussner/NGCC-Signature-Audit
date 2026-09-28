# CompactSQIsign2D2 message-retargeting reproducer

This directory reproduces the one-query fresh-message forgery against all
eight compact parameter sets in the NGCC SQIsign2D2 submission. For each
parameter set, the driver creates one deterministic key and honest signature,
then gives only the public key, signature, and three distinct target messages
to the attack routine. The routine publicly reconstructs the commitment curve,
hashes each target, and replaces only the serialized challenge field.

Every trial requires all five controls from the paper:

1. the honest signature verifies on its source message;
2. the untouched signature fails on a fresh target;
3. the retargeted signature verifies on that target;
4. the retargeted signature fails on the source message; and
5. every byte outside the challenge field remains unchanged.

Requirements are a POSIX shell, Bash, Git, GNU Make, a C compiler, and GMP.
A normal GMP development package is preferred. On x86-64 Linux, the driver can
also combine the submission's bundled header with an installed versioned GMP
runtime. Run the complete experiment with:

```sh
./run.sh
```

The script fetches pinned NGCC harness commit
`32f381e40ae2eb35c83a454e8e59b17f44c26c7d`, builds the unmodified compact
reference implementations, and runs three fresh-message forgeries for each
one. Set `NGCC_HARNESS` to an existing checkout of that exact commit to avoid
the clone. Set `CC` to select a compiler and `JOBS` to choose Make parallelism.

Success produces eight `status=PASS` lines in
`build/reproduction.txt`. The checked experiment used for the manuscript is
preserved in [`recorded_results.txt`](recorded_results.txt). Generated harness
files and binaries remain under ignored `.cache/` and `build/` directories.

The attack targets the compact verification relation specified and implemented
in the NGCC submission. The original 2025 CompactSQIsign2D2 construction uses
an additional forward-to-dual binding equality and is outside this result.
