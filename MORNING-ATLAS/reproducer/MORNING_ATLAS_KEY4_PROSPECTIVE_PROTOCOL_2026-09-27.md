# MORNING-ATLAS-128 independent-key prospective protocol

Protocol frozen before generating or inspecting key 4 on 2026-09-27.

## Selection and separation

- Use deterministic key identifier `4`, the next identifier after the earlier
  calibration keys.  No key-4 MORNING artifact existed in the workspace when
  this protocol was frozen.
- Generate all public transcripts without requesting either calibration
  secret from the collectors.
- Do not generate, load, or compare with the true `s1` or `t0` until the
  public recovery output, validation result, and artifact hashes have been
  recorded.
- Do not change recovery code or parameters during the prospective run.
- A public failure is the result; do not tune parameters and relabel a later
  run as prospective.

## Public queries

- Generate 3,000,000 accepted signatures as twelve disjoint 250,000-signature
  shards, with start indices `0, 250000, ..., 2750000`, using the corrected
  written-design sampler and the `hint-key` key-generation stream.
- Generate the separate 20,000-record hint transcript with key identifier 4.
  Its messages are the first 20,000 messages of the three-million-query set,
  so the number of distinct chosen messages remains 3,000,000.
- Merge shards in increasing start-index order.

## Frozen public recovery

1. Run `morning_hint_minimax.py` on all 20,000 hint records.
2. Run `morning_hint_integer_complete.py` with its defaults and serialize its
   `integer` matrix as signed decimal text.
3. Export the public full-`t` LWR instance with
   `morning_public_lwr_export`.
4. Run `morning_constraint_radial_lp.py` with `--outer 10`.
5. Run `morning_constraint_integer_completion.py` with the public LWR
   instance and `--time-limit 20`.
6. Run `morning_lwr_lattice_block_ladder.py` with `--samples 64`,
   `--secret-scale 18`, `--embedding-scale 1`, BKZ block sizes 10 and 20, and
   two BKZ loops.  It tries singleton blocks in the fixed order 0 through 5.
7. Accept recovery only if the implementation reports zero violations over
   every response inequality and every one of the 1,152 public LWR residuals
   is in `[-16,15]`.
8. If recovery succeeds, serialize recovered `s1`, construct an equivalent
   key from public data, and require a fresh-message signature to verify under
   the original public key.

Only after step 7 or a terminal public failure will calibration secrets be
regenerated from deterministic key identifier 4 and used to score the frozen
outputs.  Code and executable hashes are stored in the accompanying freeze
manifest.
