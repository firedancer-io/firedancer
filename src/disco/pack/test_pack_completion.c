/* Completion regressions: parsed wire, fake identity signatures,
   fixture ALT expansion. No signing, account DB/resolv, execution or replay. */
#include "fd_pack.c"
#define main retained_native_suite_main
#include "test_pack.c"
#undef main
#include <stdio.h>

typedef struct { fd_txn_p_t t; fd_acct_addr_t alt[64]; } mw_msg_t;
static mw_msg_t mw_msg;
static fd_acct_addr_t hot[2];
static fd_acct_addr_t mw_key(ulong kind,ulong id) { fd_acct_addr_t k;memset(k.b,(int)kind,32UL);memcpy(k.b+1,&id,8UL);return k; }
static uchar *mw_sv(uchar *p,ulong n) { while(n>=128UL){*p++=(uchar)((n&127UL)|128UL);n>>=7;}*p++=(uchar)n;return p; }
static uchar *mw_bytes(uchar *p,void const *b,ulong n) { memcpy(p,b,n);return p+n; }
static uchar *mw_ix(uchar *p,uchar pg,uchar const *ac,ulong n,uchar const *d,ulong z) {
  *p++=pg;p=mw_sv(p,n);p=mw_bytes(p,ac,n);p=mw_sv(p,z);return mw_bytes(p,d,z);
}
static uchar *mw_budget(uchar *p,uchar pg,uint cu,ulong fee) {
  ulong price=(fee*1000000UL+(ulong)cu-1UL)/(ulong)cu;uint loaded=65536U;uchar d[9];
  d[0]=2U;memcpy(d+1,&cu,4UL);p=mw_ix(p,pg,NULL,0UL,d,5UL);
  d[0]=3U;memcpy(d+1,&price,8UL);p=mw_ix(p,pg,NULL,0UL,d,9UL);
  d[0]=4U;memcpy(d+1,&loaded,4UL);return mw_ix(p,pg,NULL,0UL,d,5UL);
}
static uchar *mw_prefix(mw_msg_t *out,ulong id,int v0,fd_acct_addr_t const *keys,ulong n,ulong ro) {
  memset(out,0,sizeof(*out));uchar *p=out->t.payload;*p++=1U;memcpy(p,&id,8UL);memset(p+8,0x55,56UL);p+=64UL;
  if(v0)*p++=128U;
  *p++=1U;*p++=0U;*p++=(uchar)ro;p=mw_sv(p,n);p=mw_bytes(p,keys,32UL*n);memset(p,17,32UL);return p+32UL;
}
static void mw_parse(mw_msg_t *m,uchar *end) {
  m->t.payload_sz=(ushort)(end-m->t.payload);FD_TEST(m->t.payload_sz<=FD_TPU_MTU);
  FD_TEST(fd_txn_parse(m->t.payload,m->t.payload_sz,TXN(&m->t),NULL));
}
static void mw_reader(mw_msg_t *out,ulong id,uint mask,int reverse) {
  fd_acct_addr_t keys[5]={mw_key('p',id),{{0}},{{0}},{{0}},{{0}}};
  memcpy(keys[1].b,FD_COMPUTE_BUDGET_PROGRAM_ID,32UL);ulong n=3UL;
  for(ulong j=0UL;j<2UL;j++) { ulong k=reverse ? 1UL-j : j;if(mask&(1U<<k))keys[n++]=hot[k]; }
  uchar *p=mw_prefix(out,id,0,keys,n,n-1UL);p=mw_sv(p,4UL);p=mw_budget(p,1U,1000U,0UL);
  uchar ac[2]={0,0},d[20]={2,0,0,0};memcpy(d+12,&id,8UL);p=mw_ix(p,2U,ac,2UL,d,20UL);mw_parse(out,p);
}
/* shape0: static1+2; shape1: static1+27; shape2: static1+ALT63.
   All cold accounts are distinct writable declarations; no synthetic index
   editing. v0 lookups and category counts come from fd_txn_parse itself. */
static void mw_writer(mw_msg_t *out,ulong id,int shape,uint mask,uint cu,ulong fee) {
  fd_acct_addr_t keys[32];ulong nw=mask==3U ? (shape==1 ? 27UL : (shape==2 ? 1UL : 2UL)) : 1UL;
  ulong n=1UL+nw+2UL;keys[0]=mw_key('p',id);
  for(ulong i=1UL;i<=nw;i++)keys[i]=mw_key('c',id*64UL+i);
  if(mask==3U) {keys[1]=hot[0];if(shape!=2)keys[nw]=hot[1];}
  else keys[1]=hot[mask==1U ? 0 : 1];
  memcpy(keys[n-2UL].b,FD_COMPUTE_BUDGET_PROGRAM_ID,32UL);memset(keys[n-1UL].b,0,32UL);
  uchar *p=mw_prefix(out,id,shape==2,keys,n,2UL);p=mw_sv(p,4UL);p=mw_budget(p,(uchar)(n-2UL),cu,fee);
  uchar ac[2]={0,0},d[20]={2,0,0,0};memcpy(d+12,&id,8UL);p=mw_ix(p,(uchar)(n-1UL),ac,2UL,d,20UL);
  if(shape==2) {
    FD_TEST(mask==3U && n==4UL);fd_acct_addr_t table=mw_key('T',0UL);
    p=mw_sv(p,1UL);p=mw_bytes(p,&table,32UL);p=mw_sv(p,60UL);
    for(ulong i=0UL;i<60UL;i++) {*p++=(uchar)i;out->alt[i]=i==59UL ? hot[1] : mw_key('a',id*64UL+i);}
    p=mw_sv(p,0UL);
  }
  mw_parse(out,p);fd_txn_t const *t=TXN(&out->t);
  if(shape==2)FD_TEST(t->transaction_version==FD_TXN_V0 && t->addr_table_lookup_cnt==1U && t->addr_table_adtl_writable_cnt==60U && fd_txn_account_cnt(t,FD_TXN_ACCT_CAT_ALL)==64UL);
}
static fd_pack_ord_txn_t *mw_put(fd_pack_t *p,mw_msg_t const *m,ulong expiry) {
  fd_txn_e_t *e=fd_pack_insert_txn_init(p);memcpy(e->txnp,&m->t,sizeof(m->t));
  memcpy(e->alt_accts,m->alt,(ulong)TXN(&m->t)->addr_table_adtl_cnt*sizeof(fd_acct_addr_t));ulong deleted;
  FD_TEST(fd_pack_insert_txn_fini(p,e,expiry,&deleted)==0 && !deleted);return(fd_pack_ord_txn_t *)e;
}
static void mw_verify(fd_pack_t *p) { FD_TEST(!fd_pack_verify(p,pack_verify_scratch)); }
static fd_pack_t *mw_init(ulong max_txn) {
  fd_rng_new(_rng,0U,0UL);hot[0]=mw_key('K',0UL);hot[1]=mw_key('K',1UL);
  return init_all(512UL,20UL,max_txn,&outcome);
}
static void mw_done(fd_pack_t *p) { mw_verify(p);fd_pack_clear_all(p);mw_verify(p);fd_pack_delete(fd_pack_leave(p)); }
static ulong mw_refs(fd_pack_t *p,ulong j) {fd_pack_bitset_acct_mapping_t *q=bitset_map_query(p->acct_to_bitset,hot[j],NULL);return q ? q->ref_cnt : 0UL;}
static ulong mw_use(fd_pack_t *p,ulong j) {fd_pack_addr_use_t *u=acct_uses_query(p->acct_in_use,hot[j],NULL);return u ? u->in_use_by : 0UL;}
static ulong mw_sched(fd_pack_t *p,ulong bank) { return fd_pack_schedule_next_microblock(p,2000000UL,bank,FD_PACK_SCHEDULE_TXN,outcome.results); }
static void mw_order(char const *name,fd_pack_ord_txn_t const *target,fd_pack_ord_txn_t const *competitor) {
  printf("{\"case\":\"%s\",\"phase\":\"ordering\",\"target_rewards\":%u,\"target_compute\":%u,\"competitor_rewards\":%u,\"competitor_compute\":%u,\"competitor_native_ratio_higher\":%s}\n",name,target->rewards,target->compute_est,competitor->rewards,competitor->compute_est,
    (ulong)competitor->rewards*target->compute_est>(ulong)target->rewards*competitor->compute_est ? "true":"false");
  FD_TEST((ulong)competitor->rewards*target->compute_est>(ulong)target->rewards*competitor->compute_est);
}
static void mw_drain(fd_pack_t *p,ulong *readers,ulong *writers,ulong *victim) {
  for(ulong step=0UL;step<256UL;step++) {
    ulong n=mw_sched(p,0UL);if(!n)break;
    for(ulong i=0UL;i<n;i++) {ulong id=fd_ulong_load_8(outcome.results[i].txnp->payload+1UL);
      if(id==9000UL)(*victim)++;else if(id>=3000UL && id<3100UL)(*writers)++;else if(id>=1000UL && id<2000UL)(*readers)++;else FD_TEST(0);}
    FD_TEST(fd_pack_microblock_complete(p,0UL)==1);mw_verify(p);
  }
}

/* No late target-account input/rescue: after initial setup only native
   scheduling/completion, expiry, end_block and exact read-only queries run. */
static void mw_completion(char const *name,int shape,int reset) {
  fd_pack_t *p=mw_init(4UL);
  for(ulong i=0UL;i<65UL;i++) {mw_reader(&mw_msg,1000UL+i,3U,0);mw_put(p,&mw_msg,10UL);}
  mw_writer(&mw_msg,9000UL,shape,3U,4096U,1000000UL);
  fd_pack_ord_txn_t *target=mw_put(p,&mw_msg,100UL);FD_TEST((target->root&255)==3);
  ulong account_count=fd_txn_account_cnt(TXN(target->txn),FD_TXN_ACCT_CAT_ALL);
  FD_TEST(account_count==(shape==0 ? 5UL : (shape==1 ? 30UL : 64UL)) && target->expires_at==100UL);
  ulong owner_idx=FD_ORD_TXN_ROOT_PENALTY_ACCT_IDX(target->root);
  ulong owner=owner_idx==1UL ? 0UL : 1UL;ulong other=1UL-owner;
  FD_TEST(owner_idx==(owner ? (shape==0 ? 2UL : (shape==1 ? 27UL : 63UL)) : 1UL));
  mw_writer(&mw_msg,3000UL,0,1U<<other,1000U,1000000UL);fd_pack_ord_txn_t *comp=mw_put(p,&mw_msg,100UL);
  FD_TEST((comp->root&255)==3);mw_order(name,target,comp);mw_verify(p);
  ulong scheduled_readers=0UL;
  for(ulong bank=0UL;bank<17UL;bank++) {
    ulong n=mw_sched(p,bank);FD_TEST(n==(bank==16UL ? 1UL : 4UL));
    for(ulong j=0UL;j<n;j++) {ulong id=fd_ulong_load_8(outcome.results[j].txnp->payload+1UL);FD_TEST(id>=1000UL && id<1065UL);scheduled_readers++;}
    mw_verify(p);
  }
  FD_TEST(scheduled_readers==65UL && p->pending_txn_cnt==2UL);
  FD_TEST(mw_use(p,0UL) && mw_use(p,1UL));
  FD_TEST(fd_pack_expire_before(p,11UL)==0UL); /* scheduled reader objects already removed */
  if(reset) {
    fd_pack_end_block(p);mw_verify(p); /* per-account reset should recover both */
    for(ulong bank=0UL;bank<17UL;bank++)FD_TEST(!fd_pack_microblock_complete(p,bank));
  } else for(ulong bank=0UL;bank<17UL;bank++) {
    FD_TEST(fd_pack_microblock_complete(p,bank)==1);mw_verify(p);
    if(bank<16UL) {
      FD_TEST((target->root&255)==3 && (comp->root&255)==3);
      FD_TEST(mw_use(p,0UL) && mw_use(p,1UL) && !treap_ele_cnt(p->pending));
      FD_TEST(!mw_sched(p,18UL)); /* Last overlapping bank still owns both. */
    }
  }
  ulong readers=0UL,writers=0UL,victim=0UL;mw_drain(p,&readers,&writers,&victim);
  FD_TEST(!readers && writers==1UL && !p->outstanding_microblock_mask);
  for(ulong pass=0UL;pass<3UL;pass++) {fd_pack_end_block(p);mw_verify(p);mw_drain(p,&readers,&writers,&victim);}
  FD_TEST(!mw_use(p,0UL) && !mw_use(p,1UL));
  printf("{\"case\":\"%s\",\"phase\":\"complete\",\"account_count\":%lu,\"owner_index\":%lu,\"completed_readers\":%lu,\"reset_released_readers\":%lu,\"higher_priority_completed\":%lu,\"target_completed\":%lu,\"remaining\":%lu,\"A_refs\":%lu,\"B_refs\":%lu,\"A_use\":%lu,\"B_use\":%lu,\"end_blocks_after_drain\":3,\"late_input\":false,\"native_verify\":true}\n",
         name,account_count,owner_idx,reset ? 0UL : scheduled_readers,reset ? scheduled_readers : 0UL,writers,victim,p->pending_txn_cnt,mw_refs(p,0UL),mw_refs(p,1UL),mw_use(p,0UL),mw_use(p,1UL));
  fflush(stdout); /* Save the parent failure state before the recovery assertion. */
  FD_TEST(victim==1UL && !p->pending_txn_cnt);
  mw_done(p);
}

static void mw_expiry(char const *name,int shape,int reverse,int single) {
  fd_pack_t *p=mw_init(4UL);ulong count=single ? 65UL : 130UL;
  for(ulong j=0UL;j<(single ? 1UL : 2UL);j++)for(ulong i=0UL;i<65UL;i++) {
    ulong k=single ? 0UL : j;mw_reader(&mw_msg,1000UL+j*65UL+i,1U<<k,0);
    mw_put(p,&mw_msg,(k==(reverse ? 1UL : 0UL) || single) ? 10UL : 20UL);
  }
  mw_writer(&mw_msg,9000UL,shape,3U,4096U,1000000UL);fd_pack_ord_txn_t *target=mw_put(p,&mw_msg,100UL);
  FD_TEST((target->root&255)==3);int initial_root=target->root;
  mw_writer(&mw_msg,3000UL,0,1U,1000U,1000000UL);fd_pack_ord_txn_t *comp=mw_put(p,&mw_msg,100UL);mw_order(name,target,comp);
  FD_TEST(fd_pack_expire_before(p,11UL)==65UL);mw_verify(p);
  if(!single) {FD_TEST(fd_pack_expire_before(p,21UL)==65UL);mw_verify(p);}
  FD_TEST(target->root==FD_ORD_TXN_ROOT_PENDING && !mw_use(p,0UL) && !mw_use(p,1UL));
  FD_TEST(mw_refs(p,0UL)==2UL && mw_refs(p,1UL)==1UL);
  ulong readers=0UL,writers=0UL,victim=0UL;mw_drain(p,&readers,&writers,&victim);
  FD_TEST(!readers && writers==1UL && victim==1UL && !p->pending_txn_cnt);
  printf("{\"case\":\"%s\",\"phase\":\"final\",\"shape\":%d,\"initial_root\":%d,\"expired\":%lu,\"target_completed\":%lu,\"higher_priority_completed\":%lu,\"remaining\":0,\"native_verify\":true}\n",name,shape,initial_root,count,victim,writers);mw_done(p);
}

static void mw_relocation(void) {
  char const *name="colliding_expiry_ALT63";fd_pack_t *p=mw_init(4UL);
  ulong mask=penalty_map_slot_cnt(p->penalty_treaps)-1UL,seed=penalty_map_seed(p->penalty_treaps),slot=(ulong)penalty_map_key_hash(hot[0],seed)&mask;int found=0;
  for(ulong n=1UL;n<1000000UL;n++) {fd_acct_addr_t k=mw_key('Q',n);if(((ulong)penalty_map_key_hash(k,seed)&mask)==slot) {hot[1]=k;found=1;break;}}
  FD_TEST(found);
  for(ulong i=0UL;i<65UL;i++) {mw_reader(&mw_msg,1000UL+i,3U,0);mw_put(p,&mw_msg,20UL);}
  mw_writer(&mw_msg,9000UL,2,3U,4096U,1000000UL);fd_pack_ord_txn_t *target=mw_put(p,&mw_msg,100UL);
  ulong owner=FD_ORD_TXN_ROOT_PENALTY_ACCT_IDX(target->root)==1UL ? 0UL : 1UL,other=1UL-owner;
  mw_writer(&mw_msg,3000UL,0,1U<<other,1000U,1000000UL);fd_pack_ord_txn_t *comp=mw_put(p,&mw_msg,100UL);
  mw_writer(&mw_msg,3001UL,0,1U<<other,1000U,500000UL);mw_put(p,&mw_msg,100UL);mw_order(name,target,comp);
  ulong before=(ulong)penalty_map_query(p->penalty_treaps,hot[other],NULL);FD_TEST(before);
  /* One trigger enumerates owner first. Removing its now-empty tree must
     relocate the other map entry before the next account is examined. */
  mw_reader(&mw_msg,1900UL,3U,owner==1UL);mw_put(p,&mw_msg,10UL);
  FD_TEST(fd_pack_expire_before(p,11UL)==1UL);mw_verify(p);
  ulong after=(ulong)penalty_map_query(p->penalty_treaps,hot[other],NULL);
  FD_TEST(after && after!=before && target->root==FD_ORD_TXN_ROOT_PENDING);
  FD_TEST(fd_pack_expire_before(p,21UL)==65UL);mw_verify(p);
  ulong readers=0UL,writers=0UL,victim=0UL;mw_drain(p,&readers,&writers,&victim);
  FD_TEST(!readers && writers==2UL && victim==1UL && !p->pending_txn_cnt);
  printf("{\"case\":\"%s\",\"phase\":\"final\",\"actual_map_relocation\":true,\"expired\":66,\"target_completed\":1,\"higher_priority_completed\":2,\"remaining\":0,\"native_verify\":true}\n",name);mw_done(p);
}

static void mw_reused(int new_first) {
  fd_pack_t *p=mw_init(1UL);
  for(ulong i=0UL;i<2UL;i++) {mw_reader(&mw_msg,1000UL+i,3U,0);mw_put(p,&mw_msg,100UL);}
  for(ulong bank=0UL;bank<2UL;bank++)FD_TEST(mw_sched(p,bank)==1UL);
  mw_verify(p);
  FD_TEST(!mw_refs(p,0UL) && !mw_refs(p,1UL));
  FD_TEST((mw_use(p,0UL)&FD_PACK_IN_USE_BIT_CLEARED) && (mw_use(p,1UL)&FD_PACK_IN_USE_BIT_CLEARED));
  /* Recreate mappings while old readers retain their original execution uses. */
  for(ulong i=0UL;i<65UL;i++) {mw_reader(&mw_msg,1100UL+i,3U,0);mw_put(p,&mw_msg,100UL);}
  mw_writer(&mw_msg,9000UL,0,3U,4096U,1000000UL);fd_pack_ord_txn_t *target=mw_put(p,&mw_msg,100UL);
  ulong other=FD_ORD_TXN_ROOT_PENALTY_ACCT_IDX(target->root)==1 ? 1UL : 0UL;
  mw_writer(&mw_msg,3000UL,0,1U<<other,1000U,1000000UL);fd_pack_ord_txn_t *comp=mw_put(p,&mw_msg,100UL);
  FD_TEST((target->root&255)==3 && (comp->root&255)==3);
  FD_TEST(mw_sched(p,2UL)==1UL);
  FD_TEST(fd_ulong_load_8(outcome.results[0].txnp->payload+1UL)>=1100UL);
  FD_TEST(!(mw_use(p,0UL)&FD_PACK_IN_USE_BIT_CLEARED) && !(mw_use(p,1UL)&FD_PACK_IN_USE_BIT_CLEARED));
  mw_verify(p);
  ulong order[3]={new_first ? 2UL : 0UL,new_first ? 0UL : 1UL,new_first ? 1UL : 2UL};
  for(ulong i=0UL;i<3UL;i++) {
    FD_TEST(fd_pack_microblock_complete(p,order[i])==1);mw_verify(p);
    if(i<2UL)FD_TEST((target->root&255)==3 && (comp->root&255)==3 && mw_use(p,0UL) && mw_use(p,1UL));
  }
  FD_TEST(target->root==FD_ORD_TXN_ROOT_PENDING && comp->root==FD_ORD_TXN_ROOT_PENDING);
  ulong readers=0UL,writers=0UL,victim=0UL;mw_drain(p,&readers,&writers,&victim);
  FD_TEST(readers==64UL && writers==1UL && victim==1UL && !p->pending_txn_cnt);
  printf("{\"case\":\"reused_account_%s_first\",\"phase\":\"control\",\"BIT_CLEARED_observed\":true,\"new_use_cleared_flag\":true,\"last_use_guarded\":true,\"target_completed\":1,\"remaining\":0,\"pass\":true,\"native_verify\":true}\n",new_first ? "new" : "old");mw_done(p);
}

static void mw_completion_relocation(void) {
  fd_pack_t *p=mw_init(4UL);ulong mask=penalty_map_slot_cnt(p->penalty_treaps)-1UL,seed=penalty_map_seed(p->penalty_treaps);
  ulong slot=(ulong)penalty_map_key_hash(hot[0],seed)&mask;int found=0;
  for(ulong n=1UL;n<1000000UL;n++) {fd_acct_addr_t k=mw_key('Q',n);if(((ulong)penalty_map_key_hash(k,seed)&mask)==slot){hot[1]=k;found=1;break;}}
  FD_TEST(found);
  for(ulong i=0UL;i<65UL;i++) {mw_reader(&mw_msg,1000UL+i,3U,1);mw_put(p,&mw_msg,100UL);}
  mw_writer(&mw_msg,9000UL,0,3U,4096U,1000000UL);fd_pack_ord_txn_t *target=mw_put(p,&mw_msg,100UL);
  FD_TEST(target->root==FD_ORD_TXN_ROOT_PENALTY(2)); /* Owner map inserted first. */
  mw_writer(&mw_msg,3000UL,0,1U,1000U,1000000UL);fd_pack_ord_txn_t *comp=mw_put(p,&mw_msg,100UL);
  mw_writer(&mw_msg,3001UL,0,1U,1000U,500000UL);fd_pack_ord_txn_t *tail=mw_put(p,&mw_msg,100UL);
  ulong before=(ulong)penalty_map_query(p->penalty_treaps,hot[0],NULL);FD_TEST(before);mw_verify(p);
  for(ulong bank=0UL;bank<17UL;bank++) {FD_TEST(mw_sched(p,bank)==(bank==16UL ? 1UL : 4UL));mw_verify(p);}
  for(ulong bank=0UL;bank<17UL;bank++) {FD_TEST(fd_pack_microblock_complete(p,bank)==1);mw_verify(p);}
  fd_pack_penalty_treap_t *after=penalty_map_query(p->penalty_treaps,hot[0],NULL);
  FD_TEST(after && (ulong)after!=before && treap_ele_cnt(after->penalty_treap)==1UL);
  FD_TEST(target->root==FD_ORD_TXN_ROOT_PENDING && comp->root==FD_ORD_TXN_ROOT_PENDING && (tail->root&255)==3);
  ulong readers=0UL,writers=0UL,victim=0UL;mw_drain(p,&readers,&writers,&victim);
  FD_TEST(!readers && writers==2UL && victim==1UL && !p->pending_txn_cnt);
  puts("{\"case\":\"completion_map_relocation\",\"phase\":\"control\",\"actual_map_relocation\":true,\"target_completed\":1,\"remaining\":0,\"pass\":true,\"native_verify\":true}");mw_done(p);
}

int main(int argc,char **argv) {
  fd_boot(&argc,&argv);rng=fd_rng_join(fd_rng_new(_rng,0U,0UL));fd_metrics_register((ulong *)fd_metrics_new(metrics_scratch,0UL));extra_verify=1;
  int minimal=argc>1 && !strcmp(argv[1],"minimal");
  mw_completion("completion_static1_2",0,0);
  if(!minimal) {
    mw_completion("completion_static1_27",1,0);mw_completion("completion_static1_ALT63",2,0);
    mw_completion("end_block_static1_27_control",1,1);
    mw_expiry("destination_only_static1",0,0,1);
    mw_expiry("expiry_A_then_B_static1_27",1,0,0);mw_expiry("expiry_B_then_A_static1_27",1,1,0);
    mw_expiry("expiry_B_then_A_ALT63",2,1,0);mw_relocation();
    mw_reused(0);mw_reused(1);mw_completion_relocation();
  }
  puts("{\"summary\":true,\"all_recovered\":true,\"structural_verify_passed\":true}");
  fd_rng_delete(fd_rng_leave(rng));fd_halt();return 0;
}
