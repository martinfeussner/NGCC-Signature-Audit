# Frozen normative model (before reading prior audit artefacts)

Timestamp: 2026-10-03 UTC.

Source read for this freeze: the submitted CEDRUS-alpha PDF only,
`sources/specs/sign-04-spec.pdf` (text independently extracted with `mutool`).  No
existing CEDRUS-alpha dossier, ledger, experiment report, or audit script was
consulted before this file was written.

## Keys and address selection

The PDF defines

* `SK = (SK.seed, SK.prf, PK.seed, PK.root)` and
  `PK = (PK.seed, PK.root)`, each component `n` bytes;
* `R = PRFMSG(SK.prf,optRand,msg)` and
  `digest = HMSG(R,PK.seed,PK.root,msg[,ctrFTS])`;
* the digest parses as a FORC message `md`, a bottom-XMSS-tree index
  `idxTree` of `h-h0` bits, and a bottom-XMSS leaf / key-pair index
  `idxLeaf` of `h0` bits.

Thus the complete bottom FORC address is
`A=(idxTree,idxLeaf)` and has `h` bits.  For a fixed key and `A`, all FORC
secret chains, their Merkle authentication paths, the compressed FORC public
key, and the hypertree signature on that FORC public key are fixed.

## FORC equations

Let `N=2^a`, `W=w'`, and let `i in {0,...,k-1}` identify one FORC tree.
`msgToIndices` parses coordinate `i` into a leaf `x_i in [0,N)` and chain
position `ell_i in [0,W)`.  The global chain index is `u_i=i*N+x_i`.

For address `A`, define

* `s_{i,x}=PRF(PK.seed,SK.seed,ADRS_FTS_PRF(A,i*N+x))`;
* `C_{i,x}(0)=s_{i,x}` and
  `C_{i,x}(j+1)=F(PK.seed,ADRS_FTS_CHAIN(A,i*N+x,j+1),C_{i,x}(j))`;
* leaf `L_{i,x}=C_{i,x}(W)`;
* `T_i` as the height-`a` Merkle root of the `N` leaves of tree `i` using
  the specified addressed `H`;
* `PK_FORC(A)=T_k(PK.seed,ADRS_FTS_ROOT(A),T_0||...||T_{k-1})`.

A FORC signature on `(x_i,ell_i)_{i<k}` contains, per coordinate,
`C_{i,x_i}(ell_i)` and the `a` siblings on the Merkle authentication path for
leaf `x_i`.  Verification advances the disclosed node by `W-ell_i` public
`F` calls, rebuilds `T_i` with the path, and compresses all roots.

Consequently, a donor at the *same complete address* `A` supplies coordinate
`i` of a target iff it selected the same leaf and an earlier or equal chain
position:

`x_i^donor=x_i^target` and `ell_i^donor <= ell_i^target`.

The adversary advances `C(ell_i^donor)` by
`ell_i^target-ell_i^donor` calls and reuses that donor's authentication path.
This yields exactly the target coordinate.  Mixing coordinates is valid
because all donors at `A` have the same `T_i` and hence the same
`PK_FORC(A)`.  A full hypertree suffix from any donor at `A` authenticates the
same `PK_FORC(A)`.

For uniform independent target/donor `(x,ell)`, a donor covers a fixed target
coordinate with conditional probability `(ell+1)/(N*W)`.  If the target is
chosen with `ell=W-1`, this is `1/N`.  If both positions are uniform, the
unconditional pairwise probability is `(W+1)/(2*N*W)`.

## Parameters copied from submitted PDF Table 1.1

| set | n bytes | h | d | a | k | W | len | signature bytes claimed |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 160s | 20 | 68 | 9 | 10 | 16 | 8 | 30 | 10300 |
| 160f | 20 | 66 | 17 | 7 | 28 | 4 | 40 | 19420 |
| 256s | 32 | 67 | 9 | 12 | 23 | 4 | 48 | 25568 |
| 256f | 32 | 65 | 14 | 8 | 45 | 2 | 63 | 43296 |
| 384s | 48 | 65 | 8 | 12 | 38 | 4 | 88 | 60672 |
| 384f | 48 | 65 | 12 | 10 | 51 | 2 | 80 | 76176 |
| 512s | 64 | 65 | 8 | 13 | 47 | 4 | 101 | 98048 |
| 512f | 64 | 66 | 11 | 10 | 66 | 4 | 109 | 127488 |

## PDF ambiguities frozen for later resolution

1. `HMSG` is typed with a `ctrFTS` input and the serialized signature diagram
   includes four counter bytes, but Algorithms 20/21 call `HMSG` without that
   argument; Algorithm 20 serializes `ctrFTS` without defining it; Algorithm
   21's stated length omits the four bytes.  This affects digest generation
   and exact signature length but not the coordinate-mixing lemma once valid
   signatures and their parsed address/digest are available.
2. Algorithms 20/21 repeatedly say FORS/PORS although Section 1.9 defines and
   the surrounding prose uses FORC.  The only coherent interpretation is that
   these are stale names for FORC.
3. Section 1.2 gives an inconsistent preliminary formula for `m` omitting the
   `log2 W` FORC-chain bits.  Section 1.10 and Algorithms 20/21 include
   `k(a+log2 W)` and are internally consistent with `msgToIndices`; that later
   formula is used here.
4. Algorithm 15 advances a leaf with `chainFORC(sk,0,W,...)` although the prose
   says `W` nodes including endpoints and `ell` ranges over `[0,W)`.  Algorithms
   17/18 consistently use positions `0,...,W-1` and advance by `W-ell`, so this
   model follows their exact algorithmic convention: terminal leaf is `C(W)`.
5. The table gives total `h`, not the height vector.  This attack needs only
   the complete `h`-bit address; the individual layer heights do not affect
   its probability.

These ambiguities will be resolved against the submitted implementation and
any explicit corrigenda next; no implementation behavior will be elevated to
the specification silently.
