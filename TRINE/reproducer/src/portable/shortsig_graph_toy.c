#define _POSIX_C_SOURCE 200809L
#define main archived_special_soundness_main
#include "attack_support.c"
#undef main

#if TRINE_X != 4
#error "compile this harness with PARAMS=4"
#endif

#define TOY_SEED_BITS 8
#define MAX_BATCHES 24
#define VERTICES (TRINE_X + 1)

typedef struct {
  int valid;
  Fq a[TRINE_n * TRINE_n], b[TRINE_n * TRINE_n], c[TRINE_n * TRINE_n];
} map3;

static int make_key(Fq *base, Fq *forms, Fq *ainv)
{
  uint8_t skseed[TRINE_secret_seed_bytes], pubseed[TRINE_public_seed_bytes];
  Fq A[TRINE_n*TRINE_n], B[TRINE_n*TRINE_n], C[TRINE_n*TRINE_n];
  if (bytes_from_label(skseed,sizeof(skseed),"TRINE ShortSig graph natural toy key") != 0 ||
      trine_expand_public_seed(pubseed,skseed) != 0 ||
      trine_expand_base_form(base,pubseed,TRINE_n) != 0)
    return -1;
  for (uint32_t j=0;j<TRINE_X;j++) {
    if (trine_expand_secret_matrix_pair_vartime(A,ainv+(size_t)j*TRINE_n*TRINE_n,
            skseed,TRINE_MATRIX_A,j,TRINE_n) != 0 ||
        trine_expand_secret_matrix_pair_vartime(B,NULL,skseed,TRINE_MATRIX_B,j,TRINE_n) != 0 ||
        trine_expand_secret_matrix_pair_vartime(C,NULL,skseed,TRINE_MATRIX_C,j,TRINE_n) != 0)
      return -1;
    triform_action_pullback(forms+(size_t)j*triform_element_count(TRINE_n),
                            base,A,B,C,TRINE_n);
  }
  return 0;
}

static int build_toy(commitment_batch *batch,const Fq *base,unsigned b)
{
  size_t fe=triform_element_count(TRINE_n); Fq *psi=malloc(fe*sizeof(*psi));
  if(!psi) return -1;
  for(uint32_t i=0;i<TRINE_r;i++) {
    char label[128]; uint8_t raw[TRINE_round_seed_bytes];
    snprintf(label,sizeof(label),"TRINE ShortSig natural toy batch=%u round=%u",b,i);
    if(bytes_from_label(raw,sizeof(raw),label)!=0){free(psi);return -1;}
    uint8_t *seed=batch->seeds+(size_t)i*TRINE_round_seed_bytes;
    memset(seed,0,TRINE_round_seed_bytes); seed[0]=raw[0];
    Fq *a=batch->a+(size_t)i*TRINE_n;
    uint8_t *enc=batch->encoded_psi+(size_t)i*TRINE_TRIFORM_BYTES;
    if(derive_spec_commitment(a,psi,base,seed,i)!=0 ||
       trine_codec_encode_triform(enc,TRINE_TRIFORM_BYTES,psi,TRINE_n)!=0){free(psi);return -1;}
  }
  free(psi); return 0;
}

static int get_challenge(trine_challenge_t out[TRINE_r],const commitment_batch *batch,
                         const uint8_t *m,size_t mlen)
{
  uint8_t digest[TRINE_digest_bytes];
  return transcript_digest(digest,m,mlen,batch)==0 ?
    trine_parse_hash(digest,sizeof(digest),out,TRINE_r) : -1;
}

static const Fq *form_for(const Fq *base,const Fq *forms,int label)
{ return label==TRINE_BASE_FORM_INDEX?base:forms+(size_t)label*triform_element_count(TRINE_n); }

static void response_for(Fq out[TRINE_n],const Fq *a,int label,const Fq *maps_to_base)
{
  if(label==TRINE_BASE_FORM_INDEX) memcpy(out,a,TRINE_n*sizeof(*out));
  else pmod_mat_vec_mul(out,maps_to_base+(size_t)label*TRINE_n*TRINE_n,a,TRINE_n);
}

static int verify_core(const commitment_batch *batch,const trine_challenge_t expected[TRINE_r],
                       const uint8_t *m,size_t mlen,const Fq *base,const Fq *forms,
                       const Fq *maps_to_base)
{
  size_t fe=triform_element_count(TRINE_n); Fq *cf=malloc(fe*sizeof(*cf));
  uint8_t *enc=malloc(TRINE_TRIFORM_BYTES); uint8_t digest[TRINE_digest_bytes];
  trine_challenge_t got[TRINE_r]; trine_hash_state h; int active=0,ok=-1;
  if(!cf||!enc||trine_hash_init(&h)!=0) goto done;
  active=1;
  if(mlen&&trine_hash_absorb(&h,m,mlen)!=0) goto done;
  for(int i=0;i<TRINE_r;i++) {
    Fq d[TRINE_n]; int c=expected[i];
    response_for(d,batch->a+(size_t)i*TRINE_n,c,maps_to_base);
    if(canonical_form_vartime(cf,form_for(base,forms,c),d,TRINE_n)!=0 ||
       trine_codec_encode_triform(enc,TRINE_TRIFORM_BYTES,cf,TRINE_n)!=0 ||
       memcmp(enc,batch->encoded_psi+(size_t)i*TRINE_TRIFORM_BYTES,TRINE_TRIFORM_BYTES)!=0 ||
       trine_hash_absorb(&h,enc,TRINE_TRIFORM_BYTES)!=0) goto done;
  }
  if(trine_hash_finalize(&h,digest,sizeof(digest))!=0) goto done;
  active=0; trine_hash_release(&h);
  if(trine_parse_hash(digest,sizeof(digest),got,TRINE_r)!=0) goto done;
  ok=memcmp(got,expected,sizeof(got))==0?0:-1;
done:
  if(active) trine_hash_release(&h);
  free(cf);
  free(enc);
  return ok;
}

static int edge_extract(map3 *out,int c1,const Fq *p1,int c2,const Fq *p2,
                        const Fq *base,const Fq *forms)
{
  size_t me=(size_t)TRINE_n*TRINE_n,fe=triform_element_count(TRINE_n);
  Fq x1a[me],x1b[me],x1c[me],x2a[me],x2b[me],x2c[me];
  Fq i2a[me],i2b[me],i2c[me]; Fq *cf1=malloc(fe*sizeof(*cf1)),*cf2=malloc(fe*sizeof(*cf2));
  int ret=-1;if(!cf1||!cf2)goto done;
  if(canonical_certificate(x1a,x1b,x1c,cf1,form_for(base,forms,c1),p1)!=0 ||
     canonical_certificate(x2a,x2b,x2c,cf2,form_for(base,forms,c2),p2)!=0 ||
     memcmp(cf1,cf2,fe*sizeof(*cf1))!=0 ||
     pmod_mat_inv_vartime(i2a,x2a,TRINE_n)!=0 ||
     pmod_mat_inv_vartime(i2b,x2b,TRINE_n)!=0 ||
     pmod_mat_inv_vartime(i2c,x2c,TRINE_n)!=0)goto done;
  pmod_mat_mul(out->a,x1a,i2a,TRINE_n);pmod_mat_mul(out->b,x1b,i2b,TRINE_n);
  pmod_mat_mul(out->c,x1c,i2c,TRINE_n);out->valid=1;ret=0;
done:free(cf1);free(cf2);return ret;
}

static int invert_map(map3 *out,const map3 *in)
{
  if(pmod_mat_inv_vartime(out->a,in->a,TRINE_n)!=0 ||
     pmod_mat_inv_vartime(out->b,in->b,TRINE_n)!=0 ||
     pmod_mat_inv_vartime(out->c,in->c,TRINE_n)!=0)return -1;
  out->valid=1;return 0;
}

static int compose_to_base(map3 maps[VERTICES],map3 edge[VERTICES][VERTICES])
{
  size_t me=(size_t)TRINE_n*TRINE_n; int known[VERTICES]={0};
  pmod_mat_identity(maps[TRINE_BASE_FORM_INDEX].a,TRINE_n);
  pmod_mat_identity(maps[TRINE_BASE_FORM_INDEX].b,TRINE_n);
  pmod_mat_identity(maps[TRINE_BASE_FORM_INDEX].c,TRINE_n);
  maps[TRINE_BASE_FORM_INDEX].valid=1;
  known[TRINE_BASE_FORM_INDEX]=1;
  for(int pass=0;pass<VERTICES;pass++)for(int u=0;u<VERTICES;u++)if(!known[u])
    for(int v=0;v<VERTICES;v++)if(known[v]&&edge[u][v].valid){
      Fq tmp[me];
      pmod_mat_mul(tmp,edge[u][v].a,maps[v].a,TRINE_n);memcpy(maps[u].a,tmp,sizeof(tmp));
      pmod_mat_mul(tmp,edge[u][v].b,maps[v].b,TRINE_n);memcpy(maps[u].b,tmp,sizeof(tmp));
      pmod_mat_mul(tmp,edge[u][v].c,maps[v].c,TRINE_n);memcpy(maps[u].c,tmp,sizeof(tmp));
      maps[u].valid=1;known[u]=1;break;
    }
  for(int i=0;i<VERTICES;i++) {
    if(!known[i]) return -1;
  }
  return 0;
}

int main(void)
{
  size_t fe=triform_element_count(TRINE_n),me=(size_t)TRINE_n*TRINE_n;
  Fq *base=malloc(fe*sizeof(*base)),*forms=malloc(TRINE_X*fe*sizeof(*forms));
  Fq *true_maps=malloc(TRINE_X*me*sizeof(*true_maps)),*recovered=calloc(VERTICES*me,sizeof(*recovered));
  commitment_batch **batch=calloc(MAX_BATCHES,sizeof(*batch));
  trine_challenge_t (*chal)[TRINE_r]=calloc(MAX_BATCHES,sizeof(*chal));
  map3 edge[VERTICES][VERTICES], recovered3[VERTICES];
  memset(edge,0,sizeof(edge));memset(recovered3,0,sizeof(recovered3));
  int made=0,connected=0,edge_count=0;double start=now_seconds();
  if(!base||!forms||!true_maps||!recovered||!batch||!chal||make_key(base,forms,true_maps)!=0)return 2;
  for(int b=0;b<MAX_BATCHES&&!connected;b++){
    char msg[64];int ml=snprintf(msg,sizeof(msg),"TRINE ShortSig natural toy message %d",b);
    batch[b]=malloc(sizeof(*batch[b]));
    if(!batch[b]||build_toy(batch[b],base,(unsigned)b)!=0||
       get_challenge(chal[b],batch[b],(uint8_t*)msg,(size_t)ml)!=0||
       verify_core(batch[b],chal[b],(uint8_t*)msg,(size_t)ml,base,forms,true_maps)!=0)return 2;
    made++;
    for(int old=0;old<b;old++)for(int i=0;i<TRINE_r;i++){
      int u=chal[old][i],v=chal[b][i];if(u==v||edge[u][v].valid)continue;
      if(memcmp(batch[old]->seeds+(size_t)i*TRINE_round_seed_bytes,
                batch[b]->seeds+(size_t)i*TRINE_round_seed_bytes,TRINE_round_seed_bytes)!=0)continue;
      if(memcmp(batch[old]->encoded_psi+(size_t)i*TRINE_TRIFORM_BYTES,
                batch[b]->encoded_psi+(size_t)i*TRINE_TRIFORM_BYTES,TRINE_TRIFORM_BYTES)!=0)return 2;
      Fq p1[TRINE_n],p2[TRINE_n];response_for(p1,batch[old]->a+(size_t)i*TRINE_n,u,true_maps);
      response_for(p2,batch[b]->a+(size_t)i*TRINE_n,v,true_maps);
      if(edge_extract(&edge[u][v],u,p1,v,p2,base,forms)!=0||invert_map(&edge[v][u],&edge[u][v])!=0)return 2;
      edge_count++;
    }
    memset(recovered3,0,sizeof(recovered3));
    connected=compose_to_base(recovered3,edge)==0;
  }
  if(!connected)return 1;
  int relations=1;Fq *check=malloc(fe*sizeof(*check));
  for(int j=0;j<TRINE_X;j++){
    triform_action_pullback(check,forms+(size_t)j*fe,
                            recovered3[j].a,recovered3[j].b,recovered3[j].c,TRINE_n);
    relations &= memcmp(check,base,fe*sizeof(*check))==0;
    memcpy(recovered+(size_t)j*me,recovered3[j].a,me*sizeof(*recovered));
  }
  pmod_mat_identity(recovered+(size_t)TRINE_BASE_FORM_INDEX*me,TRINE_n);
  memset(true_maps,0,TRINE_X*me*sizeof(*true_maps));
  commitment_batch *fresh=malloc(sizeof(*fresh));trine_challenge_t fc[TRINE_r];
  const uint8_t fm[]="TRINE ShortSig connected witness fresh forgery";
  if(!fresh||build_batch(fresh,base,"TRINE ShortSig graph fresh full-entropy batch")!=0||
     get_challenge(fc,fresh,fm,sizeof(fm)-1)!=0)return 2;
  int forge=verify_core(fresh,fc,fm,sizeof(fm)-1,base,forms,recovered)==0;
  Fq *badmaps=malloc(VERTICES*me*sizeof(*badmaps));memcpy(badmaps,recovered,VERTICES*me*sizeof(*badmaps));
  int hit=-1;for(int i=0;i<TRINE_r;i++)if(fc[i]<TRINE_X){hit=fc[i];break;}
  badmaps[(size_t)hit*me]=GF_add(badmaps[(size_t)hit*me],1);
  int badreject=verify_core(fresh,fc,fm,sizeof(fm)-1,base,forms,badmaps)!=0;
  printf("schema=trine-shortsig-natural-graph-toy-v1\n");
  printf("parameter_shape=ShortSig-I n=%d q=%d r=%d K=%d X=%d\n",TRINE_n,TRINE_q,TRINE_r,TRINE_K,TRINE_X);
  printf("toy_seed_bits=%d sampling=independent_fresh_uniform\n",TOY_SEED_BITS);
  printf("generated_valid_signatures=%d extracted_undirected_edges=%d\n",made,edge_count);
  printf("collision_graph_connected=%s\n",connected?"PASS":"FAIL");
  printf("each_edge_full_certificate_checked=PASS\n");
  printf("all_composed_full_tensor_relations=%s\n",relations?"PASS":"FAIL");
  printf("original_signing_matrices_erased_before_forgery=PASS\n");
  printf("connected_witness_fresh_message_forgery=%s\n",forge?"PASS":"FAIL");
  printf("negative_corrupted_map_rejected=%s\n",badreject?"PASS":"FAIL");
  printf("elapsed_seconds=%.6f\n",now_seconds()-start);
  printf("overall=%s\n",(relations&&forge&&badreject)?"PASS":"FAIL");
  for(int i=0;i<made;i++) free(batch[i]);
  free(fresh);
  free(check);
  free(badmaps);
  free(base);free(forms);free(true_maps);free(recovered);free(batch);free(chal);
  return relations&&forge&&badreject?0:1;
}
