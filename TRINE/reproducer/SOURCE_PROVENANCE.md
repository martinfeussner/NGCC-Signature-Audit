# Authoritative source provenance

The reproducer was prepared from the NGCC TRINE submission archived on
3 October 2026.

```text
dbd62aefe11d21091e9e04f387b9918aff1e63a1b9bde009387840aa33728259  sign-30-spec.pdf
4b22f54b07509833b08d32402ffe06d7566e4c87622f9931079e791c80f4765d  sign-30.zip
```

The specification is *The TRINE Signature Scheme: Algorithm Specifications
and Supporting Documentation* by Gang Tang, Debiao He, Yu Dai, Cong Peng, Min
Luo, Yinan Li, Xinyi Huang, Runqing Xu, Zihao Yu, and Bingbing Xia.

The submitted source is redistributed here only in the minimum level-I form
needed to rebuild the experiment. The two patch files document every
attack-relevant change.

`src/pdf_full_entropy/` is the reference source after only the minimal
salt-removal/signature-layout patch; it keeps the submitted 128-bit level-I
round-seed width.  `src/native/` is the separately instrumented reduced-seed
hostile-test source.  Both are derived from the archived source hash above.
