# CEDRUS-alpha key-lifetime and counter audit

Date: 2026-10-03 UTC

## Verdict

The submitted CEDRUS-alpha package does **not** specify a maximum number of
signatures per key.  In particular, it does not impose a `2^64` or `2^80`
per-key signing limit.  Section 3.2 of the submitted specification instead
introduces `q_sig` as an unconstrained variable denoting the overall number of
signing queries and gives the claimed concrete forgery probability as a
function of that variable.

The package also does **not** contain a complete counter-pruning mechanism.
There are several counter-bearing remnants in the PDF, including one nominal
four-byte allocation in the data-format figure, but there is no counter
generation algorithm, acceptance predicate, rejection loop, counter
distribution, complete serialization rule, verifier parser, or coherent size
allocation.  The executable algorithms, all sixteen submitted source trees,
all eight KAT families, the verifier length check, Table 1.1, and Equation
(4.1) consistently implement a counter-free scheme.

The defensible specification repair is therefore to remove the stale counter
and `+C` remnants and use

```
digest = HMSG(R, PK.seed, PK.root, msg)
signature = R || sigma_FORC || sigma_HT.
```

A reader who insists on every isolated PDF token literally instead obtains an
incomplete specification, not an alternative counter-pruned algorithm.  No
counter-conditioned digest distribution can be derived from the submission.

## Submitted material audited

The archive contains eight parameter profiles in each of two implementation
families, for sixteen source trees total:

```
Implementations/{Reference_Implementation,Optimized_Implementation}/
    CEDRUSALPHA-{160s,160f,256s,256f,384s,384f,512s,512f}/
```

All regular files in those trees were searched.  The top-level algorithm PDF,
both English and Chinese basic-information PDFs, all eight English/Chinese IP
PDFs, all sixteen READMEs, and all top-level and per-tree KAT files were also
searched.  The basic-information PDFs contain only the algorithm category and
submitter/contact data; neither contains a security or usage-limit statement.
The IP declarations contain no relevant statement.

### Exact primary-input hashes

All paths below are relative to the root of `sign-04.zip`.

| Input | SHA-256 |
|---|---|
| submitted `sign-04.zip` | `b90559ca94bda0130420f91fa52eeb242063a57188c766037c1b234ec3af563b` |
| `Algorithm specifications.pdf` | `7be965ae53188beec23ca4543743402509e2ae1880630b19ab1dbd29b4d70e03` |
| `Basic information/算法基本信息-英文.pdf` | `dc228e1ef31ce4405b87fc2b319b82ecbb071842a27301c49f4fce5f601f3fff` |
| `中文资料/算法基本信息-中文.pdf` | `dee83f7539b4ee04637c26002bfb5fbc83ea3f3d722d9b77f8c001a032c1f1b7` |
| `Intellectual property/知识产权声明-英文-Fangyu Zheng.pdf` | `a3a42055672c851509f69fe112869c20ffb46d0d1d33b8962bc33e7c9145f4f6` |
| `Intellectual property/知识产权声明-英文-Siwei Sun.pdf` | `769d5b8fdc81e0043801efeb7292304b40a8eb435407d46bda9006e372daf997` |
| `Intellectual property/知识产权声明-英文-Zhen Qin.pdf` | `3a994b51b799418156f23a4176a4aecf720061c84a9bb63fc73665ec32e6c1cb` |
| `Intellectual property/知识产权声明-英文-Zhiyu Zhang.pdf` | `9bb6cc5eb827097a3b33a8bd2af0b51f970bcfd6a59b5e6de33da3e122221e43` |
| `中文资料/知识产权声明-中文-孙思维.pdf` | `b4a7905cacf069361b30d2a6104bd0cdb6faee4b85b8f50cc3faa3f8e66fc354` |
| `中文资料/知识产权声明-中文-张志宇.pdf` | `af62c3978db8c6e9cb03d6e87188265756c1e7f29d5992f5db500be69de067bf` |
| `中文资料/知识产权声明-中文-秦臻.pdf` | `56c031c76308aaae0c7ea50ed66eed7d3e252718255594aa36d1031e8a94ba5c` |
| `中文资料/知识产权声明-中文-郑昉昱.pdf` | `e180b084aedcef8bc76d36b3e1eacfa778aba858f13bc52ff67f130c6e5edcad` |

The related current paper was independently checked as security-claim
material: Zhen Qin, Siwei Sun, and Fangyu Zheng, *Extending the SPHINCS+
Framework: Varying the Tree Heights and Chain Lengths*, IACR ePrint 2025/2236,
revision dated 2026-09-06, downloaded from
<https://eprint.iacr.org/2025/2236.pdf>.  Its SHA-256 is
`c9333a50f950ef7fa495668309bee3f89a1fe73ca27bb7a77e1e630b5af74fae`.

## Key-lifetime and signing-query audit

### Submitted specification

- PDF page 11, opening of Chapter 1, lists the requested classical and quantum
  security levels.  The `80-bit` text there is the Category-I quantum-security
  target, not a signing limit.  Table 1.1 on PDF page 37 likewise uses `80` in
  the `Quantum Sec. (Bits)` column.
- Section 1.4, PDF page 15, says that the virtual hypertree has `2^h` FORS
  instances.  This describes the address space.  It does not say that a key may
  sign at most `2^h` messages.
- Section 3.2, PDF page 45, says, in substance, “Let `q_sig` be the number of
  signing queries overall,” and Equations (3.1)--(3.2) retain `q_sig` as a free
  variable.  The section neither bounds it nor turns it into a per-key usage
  rule.
- No occurrence of “key lifetime,” “maximum signatures,” “per-key,” `2^64`, or
  `2^80` as a signing cap occurs in the 53-page PDF.  The PDF's other references
  to many previously issued signatures and to security bits are analytic
  statements, not operational limits.

### Submitted documentation and source

- The sixteen `README.txt` files are byte-identical.  They contain generic NGCC
  build/KAT instructions only.  They give no key state, query budget, or key
  rotation rule.
- `sign.c:49-52` documents the secret key as
  `SK_SEED || SK_PRF || PUB_SEED || root`.  Key generation and signing contain
  no persistent usage counter and accept no lifetime state.
- Across all sixteen source trees, there are zero matches for `q_sig` and
  `lifetime`, and zero `2^80` matches.
- The only `2^64` match is `address.c:20-23`, in all sixteen trees:
  `set_tree_addr` is guarded by the compile-time error “Subtree addressing is
  currently limited to at most 2^64 trees” and writes a `uint64_t` tree address.
  This is an encoding-width restriction on a tree index.  It is not a limit on
  signatures, signing queries, or key lifetime.

### Related ePrint: ordinary and reduced-capacity designs are separate

The related ePrint reinforces this distinction, although its parameter sets are
not the NGCC parameter sets.

- Section 5.2, physical PDF page 24, introduces ordinary CEDRUS-alpha and sends
  its security argument to Section R.3.  Section R.2, physical PDF page 72,
  states Theorem 7 with `q_s` as “the number of signing queries”; it does not
  impose a numerical cap.  Section R.3, physical PDF page 73, adapts that
  reduction to CEDRUS-alpha without adding one.
- A distinct Section 5.5 is explicitly titled “CEDRUS Supporting Less than
  2^64 Signatures.”  It starts on physical PDF page 27 and continues on page 28
  (zero-based PDF-renderer pages P26--P27).  That section says the reduced
  signing capacity is deliberately traded for performance and discusses
  separate smaller-scheme parameter searches.
- Table 20 on physical PDF page 76 confirms that the paper's ordinary examples
  are different parameter sets: for example, its CEDRUS-alpha-128 profiles use
  `n = 16`, whereas the NGCC submission's lowest profiles are named 160s/160f
  and use `n = 20`; the remaining level names and dimensions also differ.

It would therefore be incorrect to transfer the special Section 5.5 capacity
limit to the NGCC CEDRUS-alpha parameter sets, or to reinterpret the source
tree's 64-bit address representation as that separate usage policy.

## Exhaustive PDF counter inventory

The following are all literal `ctr`/“counter” occurrences in the submitted
algorithm PDF, plus the data-format allocation that has no literal `ctr` label.

| Location | What the PDF says | Consistency check |
|---|---|---|
| Section 1.3, Equation (1.3), PDF p.15 | Declares `H_MSG` with an extra counter-domain argument (typeset as a counter-indexed byte-string space). | On the same page, the overview equation immediately below computes `digest = H_MSG(R, PK.seed, PK.root, msg)` with no counter. |
| Section 1.6.3, PDF p.23 | Prose says Lines “?? and 1” of Algorithm 7 extract “the counter and array” from a WOTS-alpha signature. | Figure 1.10 on p.22 defines the signature as exactly `len*n` bytes; Algorithm 7 on p.24 line 1 only calls `SIG_OTS.getNodeArray()` and contains no counter extraction or check. |
| Figure 1.14, PDF p.34 | Labels the middle component `SIG_FORS+C` with size `4 + k(a+1)n`, and the hypertree component with size `4d + (h+d*len)n`. | The surrounding prose calls these FORS and hypertree signatures.  Algorithms 17--18 specify FORC, not FORS+C.  No hypertree counter is named anywhere in Algorithms 11--12 or 20--21. |
| Algorithm 20, PDF p.35, line 4 | Computes `digest = H_MSG(R, PK.seed, PK.root, msg)`. | No counter input, loop, or predicate appears before or after this line. |
| Algorithm 20, PDF p.35, line 16 | Serializes `R || ctr_FTS || sigma_FORS || sigma_HT`. | `ctr_FTS` has never been assigned, typed, sampled, incremented, or checked.  Line 13 signs the first digest directly. |
| Algorithm 21, PDF p.36, lines 1 and 4--7 | Requires the counter-free length, extracts only `R`, `SIG_FORS`, and `SIG_HT`, then computes `H_MSG(R, PK.seed, PK.root, msg)`. | There is no counter parser, no counter passed to `H_MSG`, and no pruning-predicate check. |
| Table 1.2, PDF p.38 | Writes `H_MSG(R, PK.seed, PK.root, M, ctr) = XOF_SM3(R || PK.seed || PK.root || M || ctr, 8m)` for the 160/256 instantiations. | Both caller algorithms omit the argument; the source hashes only `R || PK || M`. |
| Table 1.3, PDF p.39 | Repeats the same counter-bearing definition for 384/512. | Same contradiction. |

The `ctr` token therefore occurs six times when the two appearances in each
instantiation-table row are counted separately: once in Equation (1.3), once as
`ctr_FTS` in Algorithm 20, twice on page 38, and twice on page 39.  The word
“counter” occurs once, in the stale Algorithm-7 prose on page 23.

Section 2's opening paragraph on PDF page 41 additionally says the few-time
signature is optimized using “forced pruning,” but the chapter supplies no
forced-pruning construction.  Section 3.2's actual FORC analysis on page 45
contains no counter or rejection condition.  The lone reference to the forced-
pruning paper on page 53 does not fill in the missing algorithm.

## Serialization and size contradiction

Algorithm 21's exact length check (PDF p.36, line 1) and performance Equation
(4.1) (PDF p.47) both give

```
n + k(a+1)n + d*len*n + h*n.
```

That is also exactly Table 1.1's signature size for every profile.  If Figure
1.14's nominal four-byte FTS counter and four bytes in every hypertree layer
were really serialized, each signature would instead be `4(d+1)` bytes longer:

| Profile | Table 1.1 / KAT bytes | Figure 1.14 would imply | Difference |
|---|---:|---:|---:|
| 160s | 10,300 | 10,340 | 40 |
| 160f | 19,420 | 19,492 | 72 |
| 256s | 25,568 | 25,608 | 40 |
| 256f | 43,296 | 43,356 | 60 |
| 384s | 60,672 | 60,708 | 36 |
| 384f | 76,176 | 76,228 | 52 |
| 512s | 98,048 | 98,084 | 36 |
| 512f | 127,488 | 127,536 | 48 |

The first `Sn_Len` in each of the eight top-level KAT files equals the middle
column.  Thus Figure 1.14 is not the format emitted by the submitted signer or
accepted by the submitted verifier.

## Source audit across all sixteen implementations

The files material to signing and verification are byte-identical across all
sixteen source trees.  Their common hashes are:

| File | SHA-256 |
|---|---|
| `README.txt` | `fffa60d94194f9f8d58b1dff603a55c2256a0b11d26c6240eef1744cad19a880` |
| `sign.c` | `3804d67b7bf6cef0cb2278701bdbbe945f605a5252feaaeb57a14728055b3d0e` |
| `hash_sm3.c` | `60b317a3471bb54e605e9b334f91d675161d1cbf9764905e78dffe6e4b13bea0` |
| `hash.h` | `cb23a99d00f84e9fe163a66f23e9727b9483f7823a55b9317a65ff4b26935c30` |
| `fors.c` | `a5bcb21966e251f4e8932aaa51f42f0850d695baf603e0371bebada402b34fe0` |
| `address.c` | `ff089e5ffba6527f7981c90577054ff438e6b59f73ab6c7131f76df528c5ffe0` |
| `drng.c` | `96dd4ed74277134a4addf48d2503e31447d87c727adb62ef00675568e8d58e0a` |
| `drng.h` | `35bce53098a5698310119b98c246023e61ee474e5cbffab5993a1c5ed5c1e5a5` |

The common source behavior is unambiguous:

- `sign.c:114-123` obtains `optrand`, computes `R` once, calls
  `hash_message(...)` once, and advances the output pointer by exactly `SPX_N`.
  There is no digest-rejection loop.
- `sign.c:128-131` serializes the FORC material immediately after `R` and then
  advances by exactly `SPX_FORS_BYTES`.
- `sign.c:160` returns `SPX_BYTES`.  Verification at `sign.c:184-207` requires
  exactly `SPX_BYTES`, hashes using the first `SPX_N` bytes as `R`, advances by
  `SPX_N`, parses FORC, and advances by `SPX_FORS_BYTES`.  There is no spare
  counter field.
- `hash_sm3.c:79-105` defines `hash_message` without a counter argument and
  allocates/serializes exactly `R || PK || M` before its one XOF call.
- Every profile header uses `SPX_FORS_MSG_BYTES =
  ceil((a+log2(w'))*k/8)`, `SPX_FORS_BYTES = (a+1)kn`, and at lines 48--50
  defines `SPX_BYTES = n + SPX_FORS_BYTES + d*SPX_WOTS_BYTES + hn` with no
  counter allocation.
- `fors.c:65-84` parses each ordinary message digest directly into a tree index
  and chain length.  `fors.c:113-138` signs those values directly.  It contains
  no pruning predicate or counter search.

There is no `ctr_FTS`/`ctrFTS` match anywhere in the source.  There are 208
source lines containing the English substring “counter,” all unrelated to a
signature counter:

- 160 lines are the same ten `drng.c` lines repeated in sixteen trees.
  Lines 204, 212, 215, 222, 224, 225, and 230 are the local block counter inside
  the generic `SM3_df` derivation function.  Lines 259, 311, and 312 update the
  KAT harness DRNG's `reseed_counter`.
- 16 lines are `drng.h:26`, the `reseed_counter` field of that generic DRNG.
- 16 lines are `sign.c:115`, where “counter” is an English verb in a side-channel
  comment.
- 16 lines are profile-header line 55, repeating the same English comment.

None is read from or written to a signature, passed to `hash_message`, or used
as signing-key lifetime state.

## README inventory

Each listed file has SHA-256
`fffa60d94194f9f8d58b1dff603a55c2256a0b11d26c6240eef1744cad19a880`:

| Profile | Reference file | Optimized file |
|---|---|---|
| 160s | `Implementations/Reference_Implementation/CEDRUSALPHA-160s/README.txt` | `Implementations/Optimized_Implementation/CEDRUSALPHA-160s/README.txt` |
| 160f | `Implementations/Reference_Implementation/CEDRUSALPHA-160f/README.txt` | `Implementations/Optimized_Implementation/CEDRUSALPHA-160f/README.txt` |
| 256s | `Implementations/Reference_Implementation/CEDRUSALPHA-256s/README.txt` | `Implementations/Optimized_Implementation/CEDRUSALPHA-256s/README.txt` |
| 256f | `Implementations/Reference_Implementation/CEDRUSALPHA-256f/README.txt` | `Implementations/Optimized_Implementation/CEDRUSALPHA-256f/README.txt` |
| 384s | `Implementations/Reference_Implementation/CEDRUSALPHA-384s/README.txt` | `Implementations/Optimized_Implementation/CEDRUSALPHA-384s/README.txt` |
| 384f | `Implementations/Reference_Implementation/CEDRUSALPHA-384f/README.txt` | `Implementations/Optimized_Implementation/CEDRUSALPHA-384f/README.txt` |
| 512s | `Implementations/Reference_Implementation/CEDRUSALPHA-512s/README.txt` | `Implementations/Optimized_Implementation/CEDRUSALPHA-512s/README.txt` |
| 512f | `Implementations/Reference_Implementation/CEDRUSALPHA-512f/README.txt` | `Implementations/Optimized_Implementation/CEDRUSALPHA-512f/README.txt` |

## Ambiguity that remains

The counter remnants are too incomplete to establish authorial intent.  They
look like material retained from a `+C`/forced-pruning template, but that origin
is an inference.  What can be established directly is that the counter-bearing
fragments are mutually inconsistent with the normative algorithms, accepted
length, implementation, and KATs.

If a counter-pruned variant were intended, a revised specification would have
to define at least the counter width and byte order, initial value/range,
acceptance predicate, counter search and failure behavior, whether separate
counters exist for FORC and every hypertree layer, exact hashing inputs, exact
signature layout, verifier parsing/checks, and corrected sizes.  None of those
definitions exists in the submitted package.

