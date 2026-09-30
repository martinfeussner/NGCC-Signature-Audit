# Source provenance and controlled variants

The bundled `reference/Rhyme-SHAKE-128` tree contains the 49 source files from
the submitted Rhyme-SHAKE-128 implementation with CRLF line endings normalized
to LF. The source was extracted from the official candidate archive with
SHA-256:

```text
7b509d21c6674bc23751b8743cb7c2a4a07ee295fafe04e2fa95c0613160bdfd
```

After the same line-ending normalization, every bundled source file is
byte-identical to its archive counterpart. `SOURCE_SHA256SUMS` records every
bundled source digest and is checked before each build.

The build creates four controlled variants from that tree:

| Variant | Order | Normalization | Rejection tape | First-response codec |
|---|---|---|---|---|
| `independent` | central-minus | Appendix A boundary value | submitted independent stream | submitted table; restart if unencodable |
| `reuse` | central-minus | Appendix A boundary value | Algorithm 6 `rt2` reuse | submitted table; restart if unencodable |
| `safe` | central-minus | submitted source `M` | submitted independent stream | submitted table; restart if unencodable |
| `ungated` | central-minus | Appendix A boundary value | submitted independent stream | diagnostic full-range table |

`attack-common.patch` contains the security-relevant completion: the
central-minus fixed order and the Appendix A boundary formula. It also adds a
bounds check so values absent from the submitted first-response entropy table
cause the signing loop to restart rather than indexing past that table.

`restart-counters.patch` adds counters only. `reuse-tape.patch` selects the
random-tape reuse written in Algorithm 6. `safe-m.patch` restores the source's
operationally valid normalization. `ungated-codec.patch` is used only for the
diagnostic that removes the encoder restart; signatures from that diagnostic
are not attack-oracle evidence because the pristine decoder cannot read its
extended encoding.

The manuscript's two attack runs use `reuse` and `independent`. Every emitted
signature from those runs is passed through the pristine submitted verifier
and decoder before its public recovery record is written.
