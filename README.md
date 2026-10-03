# NGCC Signature Audit

This repository contains preliminary attack reports, their LaTeX sources, and
end-to-end reproducers for eighteen NGCC signature candidates. The attacks were
found during AI-run audits by OpenAI Codex using Daybreak Blue at maximum
reasoning effort. Independent human verification is still pending unless a
scheme-specific record says otherwise.

The previously published PDF files have deliberately not been rebuilt or
renamed because external discussions link to those exact paths. Their hashes
are recorded in [`PDF_SHA256SUMS`](PDF_SHA256SUMS) and can be checked with:

```sh
./scripts/check-published-pdfs.sh
```

| Candidate | Demonstrated result | Main experiment | Paper and source | Reproducer |
|---|---|---:|---|---|
| BiT-128 | equivalent-key recovery and fresh-message forgery | 200,000--250,000 signatures | [PDF](BiT/BiT_Attack_Description.pdf) · [TeX](BiT/BiT_Attack_Description.tex) | [`BiT/reproducer`](BiT/reproducer) |
| CEDRUS-alpha | ordinary fresh-message forgery within the NGCC query budget for all eight submitted parameter sets via FORC accumulation and public-HMSG grinding | signing-query means up to 2^77.520; two reduced forgeries and an all-eight-set full-parameter FORC splice | [PDF](CEDRUS-alpha/CEDRUS-alpha_Attack_Description.pdf) · [TeX](CEDRUS-alpha/CEDRUS-alpha_Attack_Description.tex) | [`CEDRUS-alpha/reproducer`](CEDRUS-alpha/reproducer) |
| Chinith | public-key-only forgery for all 14 submitted parameter sets | zero signing queries | [PDF](Chinith/Chinith_Attack_Description.pdf) · [TeX](Chinith/Chinith_Attack_Description.tex) | [`Chinith/reproducer`](Chinith/reproducer) |
| CS-128 | equivalent-key recovery and fresh-message forgery on one fixed key | 2,300,000 signatures | [PDF](CS/CS_Attack_Description.pdf) · [TeX](CS/CS_Attack_Description.tex) | [`CS/reproducer`](CS/reproducer) |
| DARTS-128 | exact ternary-secret recovery and equivalent-key forgery on one fixed key | 17,000,000 signatures | [PDF](DARTS/DARTS_Attack_Description.pdf) · [TeX](DARTS/DARTS_Attack_Description.tex) | [`DARTS/reproducer`](DARTS/reproducer) |
| Galas S/F | exact secret-key recovery and fresh-message forgery at all four field sizes under same-key, same-message cross-variant access | two signatures per attempt; 509/512 Galas-160 message pairs on one fixed key | [PDF](Galas/Galas_Attack_Description.pdf) · [TeX](Galas/Galas_Attack_Description.tex) | [`Galas/reproducer`](Galas/reproducer) |
| Lynxer | public-key-only forgery for six 256/384/512 parameter sets | zero signing queries | [PDF](Lynxer/Lynxer_Attack_Description.pdf) · [TeX](Lynxer/Lynxer_Attack_Description.tex) | [`Lynxer/reproducer`](Lynxer/reproducer) |
| MORNING-ATLAS-128 | exact secret-component recovery and equivalent-key forgery on two keys | 3,000,000 signatures per key | [PDF](MORNING-ATLAS/MORNING-ATLAS_Attack_Description.pdf) · [TeX](MORNING-ATLAS/MORNING-ATLAS_Attack_Description.tex) | [`MORNING-ATLAS/reproducer`](MORNING-ATLAS/reproducer) |
| Qing Luan | conditional equivalent signing-witness recovery and fresh-message forgery at all four levels after complete pre-signature DRBG state rollback | two distinct-message signatures after rollback to the same state immediately before both signing calls, repeating the hidden root and public salt | [PDF](Qing-Luan/Qing_Luan_Attack_Description.pdf) · [TeX](Qing-Luan/Qing_Luan_Attack_Description.tex) | [`Qing-Luan/reproducer`](Qing-Luan/reproducer) |
| ReSolveD-alpha S/F | equivalent signing-witness recovery and fresh-message forgery at all four security levels under same-key, same-message deterministic cross-profile access | one S/F signature pair per attempt; 256/256 ReSolveD-alpha-160 key/message sweep | [PDF](ReSolveD-alpha/ReSolveD-alpha_Attack_Description.pdf) · [TeX](ReSolveD-alpha/ReSolveD-alpha_Attack_Description.tex) | [`ReSolveD-alpha/reproducer`](ReSolveD-alpha/reproducer) |
| Rhyme-SHAKE-128 | exact secret-tail recovery and fresh-message forgery on two keys under a permitted central-first specification completion | 30,000--40,000 signatures | [PDF](Rhyme/Rhyme_Attack_Description.pdf) · [TeX](Rhyme/Rhyme_Attack_Description.tex) | [`Rhyme/reproducer`](Rhyme/reproducer) |
| Shuttle | covariance key recovery and equivalent-key forgery for all three levels | 150,000--350,000 signatures in the repository release check | [PDF](Shuttle/Shuttle_Attack_Description.pdf) · [TeX](Shuttle/Shuttle_Attack_Description.tex) | [`Shuttle/reproducer`](Shuttle/reproducer) |
| Sigurd | repeated-opening witness recovery and forgery for all three levels | 4--8 signatures | [PDF](Sigurd/Sigurd_Attack_Description.pdf) · [TeX](Sigurd/Sigurd_Attack_Description.tex) | [`Sigurd/reproducer`](Sigurd/reproducer) |
| CompactSQIsign2D2 | one-query message-retargeting fresh-message forgery for all eight compact parameter sets | 24/24 forgeries from one signature per parameter set | [PDF](SQIsign2D2/SQIsign2D2_Attack_Description.pdf) · [TeX](SQIsign2D2/SQIsign2D2_Attack_Description.tex) | [`SQIsign2D2/reproducer`](SQIsign2D2/reproducer) |
| SQIsignTriangle | conditional response-rescaling fresh-message forgery for all four submitted parameter sets | 12/12 eligible first responses; one signing query per trial | [PDF](SQIsignTriangle/SQIsignTriangle_Attack_Description.pdf) · [TeX](SQIsignTriangle/SQIsignTriangle_Attack_Description.tex) | [`SQIsignTriangle/reproducer`](SQIsignTriangle/reproducer) |
| TRINE Balanced-I/ShortSig-I | equivalent signing-witness recovery and fresh-message forgery for the direct unsalted, message-independent PDF realization; the submitted salted C source is outside the attack | exact fixed-index point at `Q = 2^64 - 1`; full-dimension reduced-seed forgeries and full-entropy conformance | [PDF](TRINE/TRINE_Attack_Description.pdf) · [TeX](TRINE/TRINE_Attack_Description.tex) | [`TRINE/reproducer`](TRINE/reproducer) |
| UVW-128 | hidden-pair recovery, equivalent signing-key construction, and fresh-message forgery on one fixed key | 300 signatures | [PDF](UVW/UVW_Attack_Description.pdf) · [TeX](UVW/UVW_Attack_Description.tex) | [`UVW/reproducer`](UVW/reproducer) |
| VDOO-128 | public-key-only structural forgery against the submitted implementation | zero signing queries | [PDF](VDOO/VDOO_Attack_Description.pdf) · [TeX](VDOO/VDOO_Attack_Description.tex) | [`VDOO/reproducer`](VDOO/reproducer) |

Each candidate directory contains the published PDF, the matching `.tex`
source, and a README describing dependencies, expected runtime, scope, and
commands. Reproducers either include the exact source tree needed by the
experiment or fetch a pinned audit-harness revision or checksum-pinned official
candidate archive. Generated build products and large transcripts are ignored
by Git.

To compile the manuscripts without touching the linked PDFs, install
[`tectonic`](https://tectonic-typesetting.github.io/) and run:

```sh
./scripts/build-papers.sh
```

The command writes new PDFs under `build/papers/` and then checks the published
files against `PDF_SHA256SUMS`.

The reports distinguish attacks on a written design from failures specific to
a submitted implementation. Read the Scope section of each paper before
generalizing a result. No repository-wide software or document license is
granted by the presence of these files; the submitted candidate sources retain
their original terms.
