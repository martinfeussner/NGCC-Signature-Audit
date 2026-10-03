#!/usr/bin/env python3
"""Independent hostile-review bounds for the CEDRUS-alpha FORC mixer."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass(frozen=True)
class P:
    name: str; n: int; h: int; d: int; a: int; k: int; w: int
    olen: int; sigbytes: int; signer_hashes: int


SETS = [
    P("160s",20,68,9,10,16,8,30,10300,2743319),
    P("160f",20,66,17,7,28,4,40,19420,199011),
    P("256s",32,67,9,12,23,4,48,25568,4163230),
    P("256f",32,65,14,8,45,2,63,43296,456199),
    P("384s",48,65,8,12,38,4,88,60672,5347900),
    P("384f",48,65,12,10,51,2,80,76176,1490831),
    P("512s",64,65,8,13,47,4,101,98048,10555995),
    P("512f",64,66,11,10,66,4,109,127488,2481272),
]


def ladd(a: float, b: float) -> float:
    if a == -math.inf: return b
    if b == -math.inf: return a
    m=max(a,b)
    return m+math.log2(2**(a-m)+2**(b-m))


def mean_coverage(r: int, p: P) -> float:
    if r == 0: return 0.0
    D=(1<<p.a)*p.w
    return sum(1-(1-(ell+1)/D)**r for ell in range(p.w))/p.w


def second_coverage(r: int, p: P) -> float:
    """Second moment of a coordinate's random covered-domain fraction."""
    if r == 0: return 0.0
    B=1<<p.a; D=B*p.w
    miss=lambda z: (1-z/D)**r
    total=0.0
    for y in range(p.w):
        for z in range(p.w):
            sy,sz=y+1,z+1
            same=1-miss(sy)-miss(sz)+miss(max(sy,sz))
            diff=1-miss(sy)-miss(sz)+miss(sy+sz)
            total += B*same+B*(B-1)*diff
    return total/(D*D)


def pois_moments(qbits: float, p: P) -> tuple[float,float,int,float]:
    lam=2**(qbits-p.h)
    cutoff=max(100,math.ceil(lam+20*math.sqrt(lam+1)+100))
    l1=l2=-math.inf
    for r in range(1,cutoff+1):
        lp=(-lam+r*math.log(lam)-math.lgamma(r+1))/math.log(2)
        g=mean_coverage(r,p); s=second_coverage(r,p)
        l1=ladd(l1,lp+p.k*math.log2(g))
        l2=ladd(l2,lp+p.k*math.log2(s))
    u=cutoff+1
    tail=(-lam+u*(1+math.log(lam/u)))/math.log(2)
    return l1,l2,cutoff,tail


def pois_mean(qbits: float, p: P) -> float:
    lam=2**(qbits-p.h)
    cutoff=max(80,math.ceil(lam+14*math.sqrt(lam+1)+60))
    ans=-math.inf
    for r in range(1,cutoff+1):
        lp=(-lam+r*math.log(lam)-math.lgamma(r+1))/math.log(2)
        g=mean_coverage(r,p)
        ans=ladd(ans,lp+p.k*math.log2(g))
    return ans


def expected_compressed_bytes(qbits: float, p: P) -> float:
    """Same natural representation, independently re-derived.

    Per address and FORC coordinate retain the minimum disclosed chain node
    for each observed leaf and the Merkle frontier needed to reconstruct paths;
    retain one hypertree suffix per occupied address.
    """
    lam=2**(qbits-p.h); B=1<<p.a
    disclosed=B*(1-math.exp(-lam/B))
    frontier=0.0
    for j in range(p.a):
        frontier += (B/(1<<j))*(
            math.exp(-lam*(1<<j)/B)-math.exp(-lam*(1<<(j+1))/B))
    ht=(p.d*p.olen+p.h)*p.n
    per_addr=p.k*((p.n+1)*disclosed+p.n*frontier)+(1-math.exp(-lam))*(ht+16)
    return 2**p.h*per_addr


def expected_full_auth_bytes(qbits: float, p: P) -> float:
    """Conservative table: one complete FORC component per observed leaf.

    A retained component is its n-byte disclosed chain node, a*n-byte full
    authentication path, and one byte of chain-position metadata.  We also
    retain one complete hypertree suffix plus 16 metadata bytes per occupied
    full address.  This does not rely on Merkle-frontier compression.
    """
    lam=2**(qbits-p.h); B=1<<p.a
    leaves=B*(1-math.exp(-lam/B))
    ht=(p.d*p.olen+p.h)*p.n
    per_addr=p.k*((p.a+1)*p.n+1)*leaves+(1-math.exp(-lam))*(ht+16)
    return 2**p.h*per_addr


def hard_full_auth_bytes(p: P, prefix_bits: int) -> int:
    """Fully provision every leaf of every retained-prefix full address."""
    B=1<<p.a
    component=(p.a+1)*p.n+1
    ht=(p.d*p.olen+p.h)*p.n+16
    return (1<<(p.h-prefix_bits))*(p.k*B*component+ht)


def all_address(p: P, qbits: float) -> dict:
    l1,l2,cut,tail=pois_moments(qbits,p)
    # The omitted summands have s_r^k <= 1, so the Poisson upper-tail bound
    # is also an additive upper bound on the omitted second moment.
    l2_upper=ladd(l2,tail)
    relvar_upper=l2_upper-p.h-2*l1
    bad=2+relvar_upper
    T63=-l1+1               # if table mass >= half its mean
    # Chernoff: Pr[Pois(mu) >= K] <= exp(-mu + K(1+ln(mu/K))).
    # This is useful only below K=2^80.  At equality the displayed bound is 1.
    abort_ln=(-2**qbits + 2**80*(1+math.log(2**(qbits-80))))
    abort_log2=abort_ln/math.log(2)
    return {
        "poisson_query_mean_log2":qbits,
        "attacker_acquisition_hmsg_calls_log2":qbits,
        "mean_bucket_occupancy":2**(qbits-p.h),
        "mean_candidate_success_log2":l1,
        "candidate_trials_63pct_given_good_table_log2":T63,
        "table_lower_tail_chebyshev_log2":bad,
        "unconditional_success_lower_bound":(1-2**bad)*(1-math.exp(-1)),
        "poisson_occupancy_cutoff":cut,
        "omitted_occupancy_tail_log2":tail,
        "truncated_second_moment_log2":l2,
        "second_moment_upper_bound_log2":l2_upper,
        "second_moment_tail_incorporated":True,
        "abort_at_2^80_query_bound_log2":abort_log2,
        "abort_bound_negative_exponent_log2":(
            math.log2(-abort_log2) if abort_log2 < 0 else None),
        "returned_signature_bytes_log2":qbits+math.log2(p.sigbytes),
        "returned_signature_bits_log2":qbits+math.log2(p.sigbytes)+3,
        "compressed_table_bytes_log2":math.log2(expected_compressed_bytes(qbits,p)),
        "full_auth_table_bytes_log2":math.log2(expected_full_auth_bytes(qbits,p)),
        "record_updates_log2":qbits+math.log2(p.k),
        "honest_signer_hashes_log2":qbits+math.log2(p.signer_hashes),
    }


def optimize_all(p: P, metric: str) -> dict:
    best=None
    # Locate on a 0.05-bit grid, then refine locally to 0.005 bit.
    candidates=[p.h+z/10 for z in range(0,math.floor((79-p.h)*10)+1)]
    scored=[]
    for q in candidates:
        l1=pois_mean(q,p); h63=-l1+1
        if metric=="expected_queries_plus_inverse_mean":
            score=ladd(q,-l1)
        elif metric=="queries_plus_candidate_hashes":
            score=ladd(q,h63)
        elif metric=="attacker_io_bytes_or_hashes":
            score=max(q+math.log2(p.sigbytes),h63)
        elif metric=="attacker_io_bits_or_hashes":
            score=max(q+math.log2(p.sigbytes)+3,h63)
        elif metric=="including_honest_signer_hashes":
            score=max(q+math.log2(p.signer_hashes),
                      q+math.log2(p.sigbytes),h63)
        else: raise ValueError(metric)
        scored.append((score,q))
    coarse=min(scored)
    for z in range(-20,21):
        q=coarse[1]+z/200
        if q<p.h or q>79: continue
        l1=pois_mean(q,p); h63=-l1+1
        if metric=="expected_queries_plus_inverse_mean":
            score=ladd(q,-l1)
        elif metric=="queries_plus_candidate_hashes":
            score=ladd(q,h63)
        elif metric=="attacker_io_bytes_or_hashes":
            score=max(q+math.log2(p.sigbytes),h63)
        elif metric=="attacker_io_bits_or_hashes":
            score=max(q+math.log2(p.sigbytes)+3,h63)
        elif metric=="including_honest_signer_hashes":
            score=max(q+math.log2(p.signer_hashes),
                      q+math.log2(p.sigbytes),h63)
        if best is None or score<best[0]: best=(score,q)
    score,q=best
    row=all_address(p,q)
    row["attacker_total_hmsg_calls_log2"]=ladd(
        q,row["candidate_trials_63pct_given_good_table_log2"])
    row["optimized_metric"]=metric; row["optimized_metric_log2"]=score
    return row


def optimize_prefix_shard(p: P, prefix_bits: int) -> dict:
    """Minimize Q+T for a fixed full-address-prefix shard.

    T=2/(mu/2^b) makes conditional success at least 1-e^-1 when the
    realized sharded table mass is at least half its expectation.
    """
    best=None
    for z in range(0,math.floor((79-p.h)*20)+1):
        q=p.h+z/20
        l1=pois_mean(q,p)
        t=-l1+prefix_bits+1
        score=ladd(q,t)
        if best is None or score<best[0]: best=(score,q)
    coarse=best
    best=None
    for z in range(-30,31):
        q=coarse[1]+z/1000
        if q<p.h or q>79: continue
        l1=pois_mean(q,p)
        t=-l1+prefix_bits+1
        score=ladd(q,t)
        if best is None or score<best[0]: best=(score,q)
    score,q=best
    row=all_address(p,q)
    row["prefix_bits_retained"]=prefix_bits
    row["mean_candidate_success_log2"] -= prefix_bits
    row["candidate_trials_63pct_given_good_table_log2"] += prefix_bits
    row["compressed_table_bytes_log2"] -= prefix_bits
    row["full_auth_table_bytes_log2"] -= prefix_bits
    row["hard_full_auth_table_bytes_log2"]=math.log2(
        hard_full_auth_bytes(p,prefix_bits))
    row["table_lower_tail_chebyshev_log2"] += prefix_bits
    row["unconditional_success_lower_bound"]=(
        (1-2**row["table_lower_tail_chebyshev_log2"])*(1-math.exp(-1)))
    row["optimized_metric"]="sharded_queries_plus_candidate_hashes"
    row["optimized_metric_log2"]=score
    row["attacker_total_hmsg_calls_log2"]=score
    return row


def fixed_address(p: P) -> dict:
    best=None
    # The 160f optimum is below 2^10 retained hits; 2^14 gives a wide,
    # independently checked search interval without burdening all parameter sets.
    for r in range(1,1<<14):
        g=mean_coverage(r,p); mz=g**p.k
        qs=p.h+math.log2(r); hs=p.h-math.log2(mz)+1
        score=ladd(qs,hs)
        if best is None or score<best[0]: best=(score,r,g,mz,qs,hs)
    score,r,g,mz,qs,hs=best
    s2=second_coverage(r,p)
    pz=1/(4*(s2/(g*g))**p.k)
    # The expectation r*2^h is not a high-probability acquisition budget.
    # Doubling it gives mean 2r hits.  Multiplicative Chernoff bounds failure
    # to collect r hits by exp(-r/4).
    hp_queries=2*r*(1<<p.h)
    hp_qbits=math.log2(hp_queries)
    hp_hmsg=ladd(hp_qbits,hs)
    high_probability={
        "signing_queries":hp_queries,
        "signing_queries_log2":hp_qbits,
        "fixed_public_hmsg_trials_log2":hs,
        "attacker_total_hmsg_calls_log2":hp_hmsg,
        "hit_collection_failure_chernoff_log2":-r/(4*math.log(2)),
        "returned_signature_bytes_log2":hp_qbits+math.log2(p.sigbytes),
        "returned_signature_bits_log2":hp_qbits+math.log2(p.sigbytes)+3,
        "honest_signer_hashes_log2":hp_qbits+math.log2(p.signer_hashes),
    }
    return {
        "retained_exact_address_hits":r,
        "mean_covered_target_fraction_log2":math.log2(mz),
        "candidate_trials_63pct_given_half_mean_table_log2":hs,
        "paley_zygmund_good_table_probability":pz,
        "one_run_success_lower_bound":pz*(1-math.exp(-1)),
        "mean_hit_budget":{
            "expected_signing_queries_log2":qs,
            "expected_attacker_total_hmsg_calls_log2":score,
            "returned_signature_bytes_log2":qs+math.log2(p.sigbytes),
            "honest_signer_hashes_log2":qs+math.log2(p.signer_hashes),
        },
        "high_probability_acquisition":high_probability,
    }


def main() -> None:
    out={"model":(
        "ideal independent HMSG outputs, domain-separated FORC, ordinary hedged "
        "signatures; all-address adversary Poissonizes its query count and aborts "
        "at 2^80"),"sets":{}}
    for p in SETS:
        out["sets"][p.name]={
            "parameters":asdict(p),
            "expected_hmsg_work_optimized":optimize_all(
                p,"expected_queries_plus_inverse_mean"),
            "rigorous_hmsg_work_optimized":optimize_all(p,"queries_plus_candidate_hashes"),
        }
    p=next(x for x in SETS if x.name=="160f")
    out["160f_detailed"]={
        "fixed_address":fixed_address(p),
        "fixed_query_budgets":{str(q):all_address(p,q) for q in (64,70,71.12,72,79)},
        "attacker_io_optimized":optimize_all(p,"attacker_io_bytes_or_hashes"),
        "attacker_bitwork_optimized":optimize_all(p,"attacker_io_bits_or_hashes"),
        "service_work_optimized":optimize_all(p,"including_honest_signer_hashes"),
        "two_bit_address_prefix_filter":None,
    }
    base=out["160f_detailed"]["attacker_io_optimized"].copy()
    # Retaining only one 2-bit address-prefix shard divides expected useful
    # table mass and storage by four, while input traffic and signer work stay.
    base["prefix_bits_retained"]=2
    base["mean_candidate_success_log2"] -= 2
    base["candidate_trials_63pct_given_good_table_log2"] += 2
    base["compressed_table_bytes_log2"] -= 2
    base["full_auth_table_bytes_log2"] -= 2
    base["table_lower_tail_chebyshev_log2"] += 2
    base["optimized_metric_log2"] = max(
        base["returned_signature_bytes_log2"],
        base["candidate_trials_63pct_given_good_table_log2"])
    base["attacker_total_hmsg_calls_log2"] = ladd(
        base["poisson_query_mean_log2"],
        base["candidate_trials_63pct_given_good_table_log2"])
    base["unconditional_success_lower_bound"]=(
        (1-2**base["table_lower_tail_chebyshev_log2"])*(1-math.exp(-1)))
    out["160f_detailed"]["two_bit_address_prefix_filter"]=base

    # Conservative fixed-prefix alternatives that retain complete donor auth
    # paths.  b=6 is the first shard whose *fully provisioned* table is below
    # 2^80 bytes; this is a deterministic capacity, not an expectation.
    out["160f_detailed"]["four_bit_prefix_full_path_table"]=(
        optimize_prefix_shard(p,4))
    out["160f_detailed"]["six_bit_prefix_full_path_table"]=(
        optimize_prefix_shard(p,6))
    path=Path(__file__).with_name("hostile_complexity.json")
    path.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
    print(json.dumps(out,indent=2,sort_keys=True))


if __name__ == "__main__": main()
