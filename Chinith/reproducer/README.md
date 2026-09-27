# Chinith public-key-only forgery reproducer

`chinith_universal_forgery.c` constructs a false witness from public data,
runs the submitted prover, and asks the unmodified verifier to check the
result. It also changes one message bit and requires that control verification
to fail. The victim secret-key buffer is erased before the attack begins.

The driver covers all 14 submitted SM4th, uBlockith, and Vistrutith parameter
sets. It targets the missing `a_tilde[0]` binding in both submitted
implementation trees; the written specification includes that binding.

Requirements are a POSIX shell, Git, GNU Make, and a C compiler. Run:

```sh
./run.sh
```

The script fetches NGCC harness commit
`37ce9750cafd7ea0db0be255e4e8e02f10fe7841`, installs the included driver into
that pinned source tree, builds all parameter sets, and executes them. A
successful line ends with `public-key-only forgery accepted`. On the machine
reported in the paper, individual forgeries took 0.011--2.660 CPU-seconds.

Set `NGCC_HARNESS` to an existing checkout of that commit to avoid the clone.
