/* Bounded native integration regressions using upstream fake records.
   Compile the real implementation here for ownership/map lifetime checks. */
#ifndef FD_PACK_C_SOURCE
#define FD_PACK_C_SOURCE "fd_pack.c"
#endif
#include FD_PACK_C_SOURCE
#define main retained_native_suite_main
#include "test_pack.c"
#undef main
#include <stdio.h>
#include <time.h>

static fd_acct_addr_t H,K,J;
static fd_acct_addr_t cp_key( char c ) { fd_acct_addr_t k;memset(k.b,c,32UL);return k; }
static fd_pack_t * cp_init( void ) {
  fd_rng_new(_rng,0U,0UL);H=cp_key('H');K=cp_key('K');J=cp_key('J');
  return init_all(256UL,4UL,4UL,&outcome);
}
static void cp_verify( fd_pack_t * p ) { FD_TEST(!fd_pack_verify(p,pack_verify_scratch)); }
static void cp_done( fd_pack_t * p ) { cp_verify(p);fd_pack_clear_all(p);cp_verify(p);fd_pack_delete(fd_pack_leave(p)); }
static fd_pack_ord_txn_t *
cp_put( fd_pack_t * p,ulong id,ulong expiry,double priority,char const * w,char const * r ) {
  make_transaction(id,1000U,1024U,priority,w,r,NULL,NULL);
  fd_txn_p_t * t=txnp_scratch+id;fd_txn_t const * txn=TXN(t);
  fd_acct_addr_t * a=(fd_acct_addr_t *)(t->payload+txn->acct_addr_off);
  for(ulong i=0UL;i<txn->acct_addr_cnt;i++) {
    fd_acct_addr_t h=cp_key('H'),k=cp_key('K'),j=cp_key('J');
    if(!memcmp(a[i].b,h.b,32UL))a[i]=H;
    if(!memcmp(a[i].b,k.b,32UL))a[i]=K;
    if(!memcmp(a[i].b,j.b,32UL))a[i]=J;
  }
  fd_txn_e_t * e=fd_pack_insert_txn_init(p);memcpy(e->txnp,t,sizeof(*t));ulong deleted;
  FD_TEST(fd_pack_insert_txn_fini(p,e,expiry,&deleted)>=0 && !deleted);return (fd_pack_ord_txn_t *)e;
}
static ulong cp_refs( fd_pack_t * p,fd_acct_addr_t k ) {
  fd_pack_bitset_acct_mapping_t * q=bitset_map_query(p->acct_to_bitset,k,NULL);return q ? q->ref_cnt : 0UL;
}
static ulong cp_use( fd_pack_t * p,fd_acct_addr_t k ) {
  fd_pack_addr_use_t * u=acct_uses_query(p->acct_in_use,k,NULL);return u ? u->in_use_by : 0UL;
}
static ulong cp_schedule( fd_pack_t * p,ulong bank ) {
  return fd_pack_schedule_next_microblock(p,1000000UL,bank,FD_PACK_SCHEDULE_TXN,outcome.results);
}
static void cp_first( fd_pack_t * p,ulong id ) {
  FD_TEST(cp_schedule(p,0UL));FD_TEST(fd_ulong_load_8(outcome.results[0].txnp->payload+1UL)==id);
  FD_TEST(fd_pack_microblock_complete(p,0UL)==1);cp_verify(p);
}
static void cp_cross( ulong fillers,ulong aged,int explicit_delete,int active ) {
  fd_pack_t * p=cp_init();
  for(ulong i=0UL;i<fillers;i++)cp_put(p,i,100UL,1.0,"H","");
  if(active)cp_put(p,180UL,100UL,13.0,active==2 ? "K" : "",active==1 ? "K" : "");
  for(ulong i=0UL;i<aged;i++)cp_put(p,100UL+i,10UL,2.0,"H","K");
  if(active) {
    FD_TEST(cp_schedule(p,0UL)==2UL);
    FD_TEST(fd_ulong_load_8(outcome.results[0].txnp->payload+1UL)==180UL);
  }
  fd_pack_ord_txn_t * target=cp_put(p,200UL,100UL,12.0,"K","");
  cp_verify(p);
  if(explicit_delete) {
    for(ulong i=0UL;i<aged;i++) {
      FD_TEST(fd_pack_delete_transaction(p,txnp_get_signatures(txnp_scratch+100UL+i))==1UL);cp_verify(p);
    }
  } else FD_TEST(fd_pack_expire_before(p,11UL)==aged);
  cp_verify(p);FD_TEST(cp_refs(p,K)==1UL && target->expires_at==100UL);
  FD_TEST(target->root==FD_ORD_TXN_ROOT_PENDING);
  if(active) {
    FD_TEST(cp_use(p,K) && !cp_schedule(p,1UL));
    FD_TEST(fd_pack_microblock_complete(p,0UL)==1);
  } else { FD_TEST(!cp_use(p,K));fd_pack_end_block(p); }
  cp_first(p,200UL);cp_done(p);
  printf("{\"case\":\"cross\",\"H\":%lu,\"readers\":%lu,\"delete\":%d,\"active\":%d,\"pass\":true}\n",fillers,aged,explicit_delete,active);
}
static void cp_self( void ) {
  fd_pack_t * p=cp_init();
  for(ulong i=0UL;i<65UL;i++)cp_put(p,i,100UL,1.0,"H","");
  fd_pack_ord_txn_t * victim=cp_put(p,180UL,10UL,13.0,"H","");
  fd_pack_ord_txn_t * survivor=cp_put(p,200UL,100UL,12.0,"H","");
  FD_TEST((victim->root&255)==3 && (survivor->root&255)==3);cp_verify(p);
  FD_TEST(fd_pack_expire_before(p,11UL)==1UL);cp_verify(p);
  FD_TEST(survivor->root==FD_ORD_TXN_ROOT_PENDING);cp_first(p,200UL);cp_done(p);
  puts("{\"case\":\"own_best_victim_excluded\",\"pass\":true}");
}
static void cp_collide( fd_pack_t * p ) {
  ulong mask=penalty_map_slot_cnt(p->penalty_treaps)-1UL,seed=penalty_map_seed(p->penalty_treaps);
  ulong slot=(ulong)penalty_map_key_hash(H,seed)&mask;ulong found=0UL;
  for(ulong n=1UL;n<1000000UL && found<2UL;n++) {
    fd_acct_addr_t c=cp_key('Q');memcpy(c.b,&n,sizeof(n));
    if(((ulong)penalty_map_key_hash(c,seed)&mask)==slot) { if(!found)K=c;else J=c;found++; }
  }
  FD_TEST(found==2UL);
}
static void cp_relocation( int empty_owner ) {
  fd_pack_t * p=cp_init();cp_collide(p);
  for(ulong i=0UL;i<65UL;i++)cp_put(p,i,100UL,1.0,"H","");
  for(ulong i=0UL;i<65UL;i++)cp_put(p,100UL+i,100UL,1.0,"","K");
  if(!empty_owner)cp_put(p,200UL,100UL,12.0,"K",""); /* K map entry first. */
  cp_put(p,180UL,10UL,13.0,"H","K"); /* Victim outranks every candidate. */
  if(empty_owner) {
    cp_put(p,200UL,100UL,12.0,"K",""); /* H map entry first. */
    for(ulong i=0UL;i<65UL;i++)cp_put(p,300UL+i,100UL,1.0,"J","");
    cp_put(p,400UL,100UL,2.0,"J",""); /* Retained collision-chain witness. */
  } else {
    cp_put(p,181UL,100UL,2.0,"H","");
    /* One H candidate now wakes before K removal. Keep another H entry
       so that K removal must still relocate the live owner map entry. */
    cp_put(p,182UL,100UL,1.0,"H","");
  }
  ulong owner_before=(ulong)penalty_map_query(p->penalty_treaps,H,NULL);
  ulong witness_before=(ulong)penalty_map_query(p->penalty_treaps,empty_owner ? J : H,NULL);
  FD_TEST(owner_before && witness_before);cp_verify(p);
  FD_TEST(fd_pack_delete_transaction(p,txnp_get_signatures(txnp_scratch+180UL))==1UL);
  cp_verify(p);
  ulong witness_after=(ulong)penalty_map_query(p->penalty_treaps,empty_owner ? J : H,NULL);
  FD_TEST(witness_after && witness_after!=witness_before);
  if(empty_owner)FD_TEST(witness_after==owner_before && !penalty_map_query(p->penalty_treaps,H,NULL));
  else FD_TEST(treap_ele_cnt(penalty_map_query(p->penalty_treaps,H,NULL)->penalty_treap)==1UL);
  FD_TEST(!penalty_map_query(p->penalty_treaps,K,NULL));cp_first(p,200UL);cp_done(p);
  printf("{\"case\":\"%s\",\"actual_map_relocation\":true,\"pass\":true}\n",empty_owner ? "empty_owner_then_candidate_lookup" : "candidate_removal_moves_owner");
}
static void cp_policy_zero( void ) {
  fd_pack_t * p=cp_init();
  for(ulong i=0UL;i<65UL;i++)cp_put(p,i,100UL,1.0,"H","");
  for(ulong i=0UL;i<65UL;i++)cp_put(p,100UL+i,100UL,1.0,"","K");
  fd_pack_ord_txn_t * victim=cp_put(p,180UL,100UL,13.0,"H","K");
  fd_pack_ord_txn_t * target=cp_put(p,200UL,100UL,12.0,"K","");
  /* Same internal contract used by nonce/initializer replacement callers. */
  FD_TEST(delete_transaction(p,victim,0,0)==1UL);cp_verify(p);
  FD_TEST((target->root&255)==3);cp_done(p);
  puts("{\"case\":\"caller_promotion_disabled\",\"pass\":true}");
}
static void cp_bundle( int expiry,int promote ) {
  fd_pack_t * p=cp_init();
  for(ulong i=0UL;i<64UL;i++)cp_put(p,i,100UL,1.0,"","K");
  fd_txn_e_t * slots[2];fd_txn_e_t * const * b=fd_pack_insert_bundle_init(p,slots,2UL);
  make_transaction1(b[0]->txnp,180UL,1000U,1024U,2.0,"Z","",NULL,NULL);
  make_transaction1(b[1]->txnp,181UL,1000U,1024U,2.0,"H","K",NULL,NULL);
  fd_ed25519_sig_t sig;memcpy(&sig,txnp_get_signatures(b[0]->txnp),sizeof(sig));
  fd_pack_ord_txn_t * first=(fd_pack_ord_txn_t *)b[0];ulong deleted;
  FD_TEST(fd_pack_insert_bundle_fini(p,b,2UL,10UL,0,NULL,&deleted)>=0 && !deleted);
  FD_TEST(first->root==FD_ORD_TXN_ROOT_PENDING_BUNDLE);
  fd_pack_ord_txn_t * target=cp_put(p,200UL,100UL,12.0,"K","");cp_verify(p);
  FD_TEST((target->root&255)==3);
  if(expiry)FD_TEST(fd_pack_expire_before(p,11UL)==2UL);
  else if(promote)FD_TEST(fd_pack_delete_transaction(p,&sig)==2UL);
  else FD_TEST(delete_transaction(p,first,1,0)==2UL);
  cp_verify(p);FD_TEST(!treap_ele_cnt(p->pending_bundles));
  if(promote){FD_TEST(target->root==FD_ORD_TXN_ROOT_PENDING);cp_first(p,200UL);}
  else FD_TEST((target->root&255)==3);
  cp_done(p);printf("{\"case\":\"bundle\",\"expiry\":%d,\"promote\":%d,\"pass\":true}\n",expiry,promote);
}
static long cp_cpu( void ) { struct timespec t;FD_TEST(!clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t));return t.tv_sec*1000000000L+t.tv_nsec; }
static void cp_perf( void ) {
  for(int hot=0;hot<2;hot++)for(ulong trial=0UL;trial<3UL;trial++) {
    long ns=0L;ulong operations=0UL;
    for(ulong rep=0UL;rep<512UL;rep++) {
      fd_pack_t * p=cp_init();
      if(hot)for(ulong i=0UL;i<65UL;i++)cp_put(p,i,100UL,1.0,"H","");
      for(ulong i=0UL;i<65UL;i++)cp_put(p,100UL+i,10UL,2.0,hot ? "H" : "","K");
      if(hot)cp_put(p,200UL,100UL,12.0,"K","");
      long start=cp_cpu();ulong n=fd_pack_expire_before(p,11UL);ns+=cp_cpu()-start;
      FD_TEST(n==65UL);operations+=n;
      /* Correctness is covered with verify in regressions, outside timing. */
      fd_pack_clear_all(p);fd_pack_delete(fd_pack_leave(p));
    }
    printf("{\"case\":\"perf\",\"hot_penalty\":%d,\"trial\":%lu,\"deleted\":%lu,\"thread_cpu_ns\":%ld,\"ns_per_deleted\":%.3f}\n",hot,trial,operations,ns,(double)ns/(double)operations);
  }
}
int main(int argc,char **argv) {
  if(argc>1 && !strcmp(argv[1],"--suite")) { for(int i=1;i<argc;i++)argv[i]=argv[i+1];argc--;return retained_native_suite_main(argc,argv); }
  fd_boot(&argc,&argv);rng=fd_rng_join(fd_rng_new(_rng,0U,0UL));
  fd_metrics_register((ulong *)fd_metrics_new(metrics_scratch,0UL));extra_verify=1;
  char const * mode=argc>1 ? argv[1] : "all";
  if(!strcmp(mode,"perf"))cp_perf();
  else {
    if(!strcmp(mode,"all") || !strcmp(mode,"cross"))for(int d=0;d<2;d++)for(int a=0;a<3;a++)cp_cross(65UL,65UL,d,a);
    if(!strcmp(mode,"all") || !strcmp(mode,"controls")) { cp_cross(64UL,65UL,0,0);cp_cross(65UL,64UL,0,0);cp_policy_zero();cp_bundle(0,0); }
    if(!strcmp(mode,"all") || !strcmp(mode,"self"))cp_self();
    if(!strcmp(mode,"all") || !strcmp(mode,"empty"))cp_relocation(1);
    if(!strcmp(mode,"all") || !strcmp(mode,"relocate"))cp_relocation(0);
    if(!strcmp(mode,"all") || !strcmp(mode,"bundle")) { cp_bundle(0,1);cp_bundle(1,1); }
  }
  fd_rng_delete(fd_rng_leave(rng));fd_halt();return 0;
}
