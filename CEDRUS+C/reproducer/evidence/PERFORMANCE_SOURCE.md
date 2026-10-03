# Pinned performance source

The recovered complexity analyzer's 513.49-million-cycle CEDRUSC-160f and
8.65-billion-cycle CEDRUSC-160s signing constants come from:

```text
evidence/perf_x86_1.md
SHA-256 e3384bc9a2110bcd101a0711c1f8926c7599723ef962914515044353614c2ba6
```

That report identifies an independent reference-implementation measurement on
an Intel Core i7-12700, KAT checked before timing.  Its performance table gives
513.49 M mean cycles / 247 ms for CEDRUSC-160f signing and 8.65 G mean cycles /
4.15 s for CEDRUSC-160s signing.

The submitted PDF separately reports 335,982,300 and 5,662,176,265 cycles on
the submitter's stated platform.  Both sets of values are retained in
`results/independent-audit.json`; host-feasibility estimates use the NGCC
harness measurements.
