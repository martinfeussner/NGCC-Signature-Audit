# Shuttle covariance recovery reproducer

This driver queries the ordinary submitted signer, verifies every response,
streams the public covariance statistic, derives the omitted error from the
public key, and stops only when public completion succeeds. It then constructs
an equivalent key, signs a fresh message, requires the submitted verifier to
accept, and requires a changed-message control to reject.

It targets the reversed transition used by the NGCC specification and
reference implementation. The separately published ePrint construction uses
the intended branch direction and is outside this claim.

Requirements are a POSIX system with `fork`, Git, GNU Make, and a C compiler.
Run all three parameter sets with four worker processes using:

```sh
./run.sh 4
```

The script fetches pinned NGCC harness commit
`37ce9750cafd7ea0db0be255e4e8e02f10fe7841`, builds the included attack source
against the submitted reference code, and runs it. The driver checks every
25,000 signatures and allows up to 400,000. Reported recoveries used
150,000--225,000 signatures for Shuttle-128, 225,000 for Shuttle-256, and
325,000 for Shuttle-512. The paper's single-core times were about 5--37
minutes; worker processes reduce wall time on multicore laptops.

Set `NGCC_HARNESS` to an existing checkout of the pinned commit to avoid the
clone.
