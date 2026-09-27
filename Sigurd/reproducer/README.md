# Sigurd repeated-opening recovery reproducer

The driver collects ordinary signatures, reconstructs their public opening
positions, interpolates each repeated Reed--Solomon chunk, solves the remaining
public syndrome equations, and calls the submitted prover with the recovered
witness. It requires an accepted fresh-message forgery and rejection of an
incorrect-witness control.

Requirements are Git, GNU Make, and a C compiler. Run two deterministic keys
at each of the three submitted security levels with:

```sh
./run.sh
```

The script fetches pinned NGCC harness commit
`37ce9750cafd7ea0db0be255e4e8e02f10fe7841` and builds the attack against the
unmodified submitted reference sources. Successful output begins with
`SECURITY sign-24` and ends with `CONFIRMED`. Reported trials needed 4--8
signatures and about 0.1--16.2 CPU-seconds, depending on the level.

Set `NGCC_HARNESS` to an existing checkout of the pinned commit to avoid the
clone.
