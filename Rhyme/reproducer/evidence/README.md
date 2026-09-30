# Frozen public evidence

These four files are from the manuscript's independent-rejection-randomness
run. They contain no signing key, seed, target-secret labels, or signature
transcript.

- `rhyme.pk`: submitted API public key.
- `rhyme.recovered`: exact four-polynomial secret tail recovered from the
  public transcript.
- `rhyme.forgery`: 1,372-byte fresh-message signature constructed from the
  public key and recovered tail.
- `rhyme.forgery-message`: the 28-byte message signed by that forgery.

`../verify_evidence.sh` rebuilds the pristine verifier, checks the public-key
relation, regenerates the forgery, requires pristine verification, runs three
negative controls, and compares the regenerated files byte for byte.
