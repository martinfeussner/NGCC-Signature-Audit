#!/usr/bin/env python3
from decimal import Decimal, getcontext
from math import comb, log2

getcontext().prec = 120
D=Decimal
Q = (1 << 64) - 1
N = 1 << 128
HZ = D('1996249000')
FULL_CF = D('0.00545916303')
profiles = {
 'Balanced-I': dict(r=138,K=52,X=1,sig_bytes=3124,sign_cycles=10345068140,seed_seconds=D('0.345799062')),
 'ShortSig-I': dict(r=61,K=36,X=4,sig_bytes=1620,sign_cycles=4875380743,seed_seconds=D('0.342778750')),
}

def prob(P, d):
    p = D(d['K'])/d['r']
    X=d['X']
    return sum([D((-1)**s*comb(X,s))*((D(1)-D(s)*p*P/(X*N)).ln()*Q).exp() for s in range(X+1)], D(0))

def solve(d):
    lo,hi=0,N
    while lo+1<hi:
        mid=(lo+hi)//2
        if prob(mid,d) < D('0.5'): lo=mid
        else: hi=mid
    return hi

def l2(x): return D(x).ln()/D(2).ln()
for name,d in profiles.items():
    P=solve(d); pr=prob(P,d); prev=prob(P-1,d)
    p=D(d['K'])/d['r']
    table_cycles=D(P)*d['seed_seconds']*HZ
    target_cycles=p*Q*FULL_CF*HZ
    total=table_cycles+target_cycles
    returned=D(Q)*d['sig_bytes']*8
    raw_table_bytes=D(P)*48
    conservative_table_bytes=D(P)*80
    signer=D(Q)*d['sign_cycles']
    print(name)
    for k,v in [
      ('Q',Q),('log2Q',l2(Q)),('P',P),('log2P',l2(P)),('prob',pr),('prob_Pminus1',prev),
      ('returned_bits',int(returned)),('log2_returned_bits',l2(returned)),
      ('public_table_seeds',P),('public_table_hashes',P),
      ('raw_table_bytes_48_per_entry',int(raw_table_bytes)),('log2_raw_table_bytes',l2(raw_table_bytes)),
      ('conservative_table_bytes_80_per_entry',int(conservative_table_bytes)),('log2_conservative_table_bytes',l2(conservative_table_bytes)),
      ('table_cycles',table_cycles),('log2_table_cycles',l2(table_cycles)),
      ('target_cycles',target_cycles),('log2_target_cycles',l2(target_cycles)),
      ('attacker_cycles',total),('log2_attacker_cycles',l2(total)),
      ('signer_cycles',signer),('log2_signer_cycles',l2(signer)),
      ('nonbase_targets',p*Q),('log2_nonbase_targets',l2(p*Q))]:
        print(k, str(v) if not isinstance(v,int) else v)
    print()
