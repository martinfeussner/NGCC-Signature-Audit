#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "api.h"
#include "hostile_api.h"
#include "params.h"
#include "triform.h"
#include "trine_codec.h"
#include "trine_expand.h"
void randombytes_init(unsigned char *, unsigned char *, int);
int main(void) {
  uint8_t entropy[48], public_seed[TRINE_public_seed_bytes];
  for (int i=0;i<48;i++) entropy[i]=(uint8_t)(17+29*i);
  randombytes_init(entropy,NULL,256);
  uint8_t *pk=malloc(TRINE_PK_BYTES), *sk=malloc(TRINE_SK_BYTES);
  size_t fc=triform_element_count(TRINE_n);
  Fq *base=malloc(fc*sizeof(Fq));
  Fq *nonbase=malloc((size_t)TRINE_X*fc*sizeof(Fq));
  Fq *a=malloc((size_t)TRINE_n*sizeof(Fq));
  Fq *cf=malloc(fc*sizeof(Fq));
  if(!pk||!sk||!base||!nonbase||!a||!cf) return 1;
  if(crypto_sign_keypair(pk,sk)||trine_codec_decode_public_key_checked(public_seed,nonbase,pk,TRINE_PK_BYTES)||trine_expand_base_form(base,public_seed,TRINE_n)) return 2;
  const int trials=16;
  clock_t begin=clock();
  for(int t=0;t<trials;t++) {
    uint8_t seed[TRINE_round_seed_bytes];
    for(size_t i=0;i<sizeof(seed);i++) seed[i]=(uint8_t)(t*73+(int)i*19+5);
    if(hostile_derive_round_commitment_vartime(a,cf,base,seed,(uint32_t)(t%TRINE_r))) return 3;
  }
  clock_t end=clock();
  double sec=(double)(end-begin)/CLOCKS_PER_SEC;
  printf("profile=%s trials=%d cpu_seconds_total=%.9f per_seed=%.9f\n",TRINE_PARAMETER_SET_NAME,trials,sec,sec/trials);
  return 0;
}
