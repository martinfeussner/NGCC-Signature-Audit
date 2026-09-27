# Lynxer public-key-only forgery reproducer

The driver creates a target public key, erases its secret-key buffer, resets
the global DRNG to a separate public attacker seed, and constructs the
degenerate witness described in the paper. It confirms by direct Lynx
evaluation that the forged key is not a preimage of the victim target, runs the
submitted public prover, requires the unmodified verifier to accept, and
requires a changed-message control to reject.

The attack covers Lynxer-256s/f, Lynxer-384s/f, and Lynxer-512s/f. The two
160-bit variants use a different output relation and are outside its scope.

Requirements are a POSIX shell, `curl`, `unzip`, `sha256sum`, and a C compiler.
Run all six affected parameter sets with:

```sh
./run.sh
```

The script downloads the official Lynxer archive, requires SHA-256
`34d863f7df8979c4a5e27fcfe657ed54e81905115c0afc8ef749f50af432f928`,
and compiles each unmodified reference parameter set separately with
`-O2 -march=native -std=c99 -DXOF_PSEUDO`. Supply an existing archive through
`LYNXER_ARCHIVE=/path/to/Lynxer.zip` if desired.

All six runs should end with `RESULT=FORGERY_ACCEPTED`. The checked independent
rerun is recorded in [`independent_review_results.txt`](independent_review_results.txt);
its slowest sign-and-verify pair took about 22.5 CPU-seconds.
