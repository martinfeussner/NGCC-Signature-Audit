# CEDRUS+C prior-art checkpoint

Checked 2026-10-03 UTC.

- Live NGCC security index and candidate page:
  - https://ngcc.dev/reports/index.html
  - https://ngcc.dev/reports/sign-03.html
  - The only CEDRUS+C entry was `sign-03-1`, the submitted-code hypertree-index
    collapse.  It is distinct from the full-width-address specification attack.
- The submitted CEDRUS+C specification, section 3.2, already identifies
  same-FORS-instance accumulation and prints
  `[1-(1-2^-a)^q]^k 2^-a'`.  The generic accumulation mechanism is therefore
  not new.
- Mehdi Abri and Jonathan Katz, *Shorter Hash-Based Signatures Using Forced
  Pruning*, IACR ePrint 2025/2069, section 4.1, gives the integrated
  few-time-key occupancy mixture and multiplies it by the adversary's public
  hash-query budget.  Public target-hash amplification is therefore also
  prior art.  https://eprint.iacr.org/2025/2069
- Hülsing, Kudinov, Ronen, and Yogev, *SPHINCS+C: Compressing SPHINCS+ With
  (Almost) No Cost*, IACR ePrint 2022/778, introduces FORS+C and explicitly
  notes that the serialized public counter may be replaced by another public
  counter satisfying the forced condition.  https://eprint.iacr.org/2022/778
- PQC-X's current CEDRUS+C page reports the Algorithm-6 WOTS+C
  encoding-check omission and the submitted implementation collapse.  Both
  are distinct; the hostile model repairs the former and restores the full
  tree selector.  https://sa-ngcc.org/c/cedrus-plus-c
- Best-effort exact-name/mechanism searches of IACR ePrint and the NIST PQC
  Forum found no public CEDRUS+C result giving the present candidate-specific
  all-address concentration, prefix-sharding, and NGCC-lifetime consequence.

Any novelty statement must therefore be limited to the CEDRUS+C parameter and
unspecified-lifetime consequence, rigorous all-address/concentration analysis,
concrete `q_S/q_H` optimization, and resource accounting.  It must not claim
the generic FORS accumulation or public-hash amplification mechanisms as new.
