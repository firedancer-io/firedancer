/* Real parser/resolver/callback regression; public deterministic TEST keys only.
   Reuse the keyed-owner fixture rather than another model of resolver state. */
#define main keyed_owner_regression_main
#include "test_shred_dispatch.c"
#undef main
#include <time.h>

static fd_fec_set_t good_set;
static fd_fec_set_t const * completed_set;
static ulong equality_controls;

static ulong
cache_index( fd_fec_resolver_t * r, fd_shred_t const * s, uchar const * root, uchar const * pub ) {
  invalid_sig_key_t key;
  memcpy(key.signature,s->signature,64UL);
  memcpy(key.root,root,32UL);
  memcpy(key.pubkey,pub,32UL);
  return fd_hash(r->seed,&key,sizeof(key)) & (INVALID_SIG_CACHE_CNT-1UL);
}

static fd_bmtree_node_t
root_of( fd_shred_t const * s ) {
  uchar tree[FD_BMTREE_COMMIT_FOOTPRINT(FD_SHRED_MERKLE_LAYER_CNT)] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_node_t root;
  FD_TEST(fd_shred_merkle_root(s,tree,&root));
  return root;
}

static int
parsed_add( fd_fec_resolver_t * r, fd_shred_t const * s, uchar const * pub, uint source ) {
  ulong sz=fd_shred_sz(s);
  fd_shred_t const * parsed=fd_shred_parse((uchar const *)s,sz,32768UL);
  FD_TEST(parsed);
  fd_fec_set_t const * fec=NULL;
  fd_shred_t const * out=NULL;
  fd_bmtree_node_t root;
  fd_fec_resolver_spilled_t spill={0};
  int rv=fd_fec_resolver_add_shred(r,parsed,sz,32768UL,source,pub,&fec,&out,&root,&spill);
  FD_TEST(!spill.slot);
  if( rv==FD_FEC_RESOLVER_SHRED_COMPLETES ) completed_set=fec;
  return rv;
}

/* Each control first inserts a REAL failed equation at the SAME bucket as a
   subsequent valid input.  The valid input differs in ONLY the indicated
   verification argument.  This catches truncated equality, not merely a
   different hash bucket.  All controls then complete by legitimate repair. */
static void
check_verification_key( void ) {
  for( ulong which=0UL; which<3UL; which++ ) {
    reset_resolvers();
    make_set(SLOT+100UL+which,0U,1000UL+which,1);
    good_set=*made;
    fd_shred_t const * good=good_set.data_shreds[0].s;
    fd_bmtree_node_t good_root=root_of(good);
    fd_fec_resolver_t * r=ctxs[0].resolver;
    ulong bucket=cache_index(r,good,good_root.hash,leader.uc);
    uchar bad_wire[FD_SHRED_MAX_SZ], bad_pub[32], seed[32];
    fd_bmtree_node_t bad_root=good_root;
    ulong found=0UL;
    for( ulong j=1UL; j<65536UL; j++ ) {
      memcpy(bad_wire,good,fd_shred_sz(good)); memcpy(bad_pub,leader.uc,32UL);
      bad_root=good_root;
      if( which==0UL ) {
        memcpy(bad_wire+32UL,&j,8UL);
        if( !fd_curve25519_scalar_validate(bad_wire+32UL) || !memcmp(bad_wire,good,64UL) ) continue;
      } else if( which==1UL ) {
        make_set(good->slot,0U,j+2000UL,1);
        memcpy(bad_wire,made->data_shreds[0].b,FD_SHRED_MIN_SZ);
        memcpy(bad_wire,good->signature,64UL);
        bad_root=root_of((fd_shred_t const *)bad_wire);
        FD_TEST(memcmp(bad_root.hash,good_root.hash,32UL));
      } else {
        memset(seed,0,sizeof(seed)); memcpy(seed,&j,8UL); seed[31]=0x73U;
        fd_ed25519_public_from_private(bad_pub,seed,sha);
        FD_TEST(memcmp(bad_pub,leader.uc,32UL));
      }
      if( cache_index(r,(fd_shred_t const *)bad_wire,bad_root.hash,bad_pub)==bucket ) { found=j; break; }
    }
    FD_TEST(found);
    FD_TEST(fd_ed25519_verify(bad_root.hash,32UL,bad_wire,bad_pub,sha)==FD_ED25519_ERR_MSG);
    ulong calls=verify_calls, hits=FD_MCNT_GET(SHRED,INVALID_SIGNATURE_CACHE_HIT);
    FD_TEST(parsed_add(r,(fd_shred_t const *)bad_wire,bad_pub,FD_FEC_RESOLVER_SHRED_SRC_TURBINE)==FD_FEC_RESOLVER_SHRED_REJECTED);
    FD_TEST(verify_calls==calls+1UL && verify_result==FD_ED25519_ERR_MSG);
    FD_TEST(r->invalid_sig_valid[bucket>>6] & (1UL<<(bucket&63UL)));
    FD_TEST(parsed_add(r,good,leader.uc,FD_FEC_RESOLVER_SHRED_SRC_TURBINE)==FD_FEC_RESOLVER_SHRED_OKAY);
    FD_TEST(verify_calls==calls+2UL && verify_result==FD_ED25519_SUCCESS);
    FD_TEST(FD_MCNT_GET(SHRED,INVALID_SIGNATURE_CACHE_HIT)==hits);
    for( ulong j=0UL; j<31UL; j++ )
      FD_TEST(parsed_add(r,good_set.parity_shreds[j].s,leader.uc,FD_FEC_RESOLVER_SHRED_SRC_REPAIR)==
              (j==30UL ? FD_FEC_RESOLVER_SHRED_COMPLETES : FD_FEC_RESOLVER_SHRED_OKAY));
    FD_TEST(completed_set);
    for( ulong j=0UL; j<32UL; j++ ) {
      FD_TEST(!memcmp(completed_set->data_shreds[j].b,good_set.data_shreds[j].b,FD_SHRED_MIN_SZ));
      FD_TEST(!memcmp(completed_set->parity_shreds[j].b,good_set.parity_shreds[j].b,FD_SHRED_MAX_SZ));
    }
    equality_controls++;
  }
}

static void
check_only_equation_failures( void ) {
  reset_resolvers();
  fd_shred_t const * s=make_set(SLOT+120UL,0U,1UL,0);
  uchar bad[FD_SHRED_MAX_SZ]; memcpy(bad,s,fd_shred_sz(s)); memset(bad+32UL,0xff,32UL);
  ulong calls=verify_calls,hits=FD_MCNT_GET(SHRED,INVALID_SIGNATURE_CACHE_HIT);
  for( ulong j=0UL; j<4UL; j++ ) {
    FD_TEST(parsed_add(ctxs[0].resolver,(fd_shred_t const *)bad,leader.uc,FD_FEC_RESOLVER_SHRED_SRC_TURBINE)==FD_FEC_RESOLVER_SHRED_REJECTED);
    FD_TEST(verify_result==FD_ED25519_ERR_SIG);
  }
  FD_TEST(verify_calls==calls+4UL && FD_MCNT_GET(SHRED,INVALID_SIGNATURE_CACHE_HIT)==hits);
  for( ulong j=0UL; j<INVALID_SIG_CACHE_CNT/64UL; j++ ) FD_TEST(!ctxs[0].resolver->invalid_sig_valid[j]);
}

static void
check_repeat_at_capacity( void ) {
  fill_pools();
  fd_shred_t const * s=make_set(SLOT+128UL,0U,1UL,0);
  ulong owner=receive(s,DST_PROTO_SHRED,0,0);
  ulong n=snapshot(owner,before), calls=verify_calls;
  ulong hits=FD_MCNT_GET(SHRED,INVALID_SIGNATURE_CACHE_HIT), rejected=FD_MCNT_GET(SHRED,INITIAL_REJECTED);
  for( ulong j=0UL; j<64UL; j++ ) {
    s=j<32UL ? made->data_shreds[j].s : made->parity_shreds[j-32UL].s;
    FD_TEST(receive(s,DST_PROTO_SHRED,1,FD_FEC_RESOLVER_SHRED_REJECTED)==owner);
    FD_TEST(snapshot(owner,after)==n && !memcmp(before,after,n));
  }
  s=made->data_shreds[0].s;
  for( ulong j=0UL; j<1024UL; j++ ) {
    FD_TEST(receive(s,j&1UL ? DST_PROTO_REPAIR : DST_PROTO_SHRED,1,FD_FEC_RESOLVER_SHRED_REJECTED)==owner);
    FD_TEST(snapshot(owner,after)==n && !memcmp(before,after,n));
  }
  FD_TEST(verify_calls==calls+1UL && FD_MCNT_GET(SHRED,INVALID_SIGNATURE_CACHE_HIT)==hits+1087UL);
  FD_TEST(FD_MCNT_GET(SHRED,INITIAL_REJECTED)==rejected+1088UL);
  FD_TEST(!FD_MCNT_GET(SHRED,FEC_INCOMPLETE_EVICTED));
  /* Original contributions survive; complete all twenty pending sets with
     just the missing31 parity shreds through the REAL repair callback. */
  for( ulong tile=0UL; tile<TILES; tile++ ) for( ulong k=0UL; k<DEPTH; k++ ) {
    make_set(SLOT,control_fec[tile][k],control_salt[tile][k],1);
    for( ulong j=0UL; j<31UL; j++ )
      FD_TEST(receive(made->parity_shreds[j].s,DST_PROTO_REPAIR,1,
                     j==30UL ? FD_FEC_RESOLVER_SHRED_COMPLETES : FD_FEC_RESOLVER_SHRED_OKAY)==tile);
    fd_fec_resolver_t * r=ctxs[tile].resolver;
    set_ctx_t const * c=ctx_list_ele_peek_tail_const(r->complete_list,r->ctx_pool);
    for( ulong j=0UL; j<32UL; j++ ) FD_TEST(!memcmp(c->set->data_shreds[j].b,made->data_shreds[j].b,FD_SHRED_MIN_SZ));
  }
  FD_TEST(!FD_MCNT_GET(SHRED,FEC_INCOMPLETE_EVICTED));
  printf("{\"proof\":\"full_pool_repeat\",\"inputs\":1088,\"real_verifications\":1,\"cache_hits\":1087,\"byte_equal_snapshots\":1088,\"data_code_siblings\":64,\"repair_completions\":20,\"evictions\":0}\n");
}

static long
now_ns( void ) {
  struct timespec t; FD_TEST(!clock_gettime(CLOCK_MONOTONIC,&t));
  return t.tv_sec*1000000000L+t.tv_nsec;
}

/* Benchmarks include the production parser, initial Merkle walk, full-key
   lookup, spare restoration and rejection metrics.  No syscall send path.
   Cold-cache control clears32 validity bytes per input (reported overhead). */
static void
benchmark( ulong mode, ulong count ) {
  reset_resolvers();
  fd_fec_resolver_t * r=ctxs[0].resolver;
  fd_shred_t const * s=make_set(SLOT+140UL,0U,1UL,0);
  uchar first[FD_SHRED_MAX_SZ], second[FD_SHRED_MAX_SZ];
  memcpy(first,s,fd_shred_sz(s)); memcpy(second,first,fd_shred_sz(s));
  fd_bmtree_node_t root=root_of(s);
  if( mode==3UL ) {
    ulong bucket=cache_index(r,s,root.hash,leader.uc),found=0UL;
    for( ulong j=2UL; j<65536UL; j++ ) {
      memcpy(second+40UL,&j,8UL);
      if( cache_index(r,(fd_shred_t const *)second,root.hash,leader.uc)==bucket ) { found=j; break; }
    }
    FD_TEST(found && memcmp(first,second,64UL));
    FD_TEST(fd_ed25519_verify(root.hash,32UL,second,leader.uc,sha)==FD_ED25519_ERR_MSG);
  }
  ulong calls=verify_calls,hits=FD_MCNT_GET(SHRED,INVALID_SIGNATURE_CACHE_HIT);
  long begin=now_ns();
  for( ulong j=0UL; j<count; j++ ) {
    uchar * wire=first;
    if( mode==1UL ) memset(r->invalid_sig_valid,0,sizeof(r->invalid_sig_valid));
    if( mode==2UL ) { ulong ordinal=j+1UL; memcpy(first+40UL,&ordinal,8UL); }
    if( mode==3UL && (j&1UL) ) wire=second;
    FD_TEST(parsed_add(r,(fd_shred_t const *)wire,leader.uc,FD_FEC_RESOLVER_SHRED_SRC_TURBINE)==FD_FEC_RESOLVER_SHRED_REJECTED);
  }
  long elapsed=now_ns()-begin;
  calls=verify_calls-calls; hits=FD_MCNT_GET(SHRED,INVALID_SIGNATURE_CACHE_HIT)-hits;
  FD_TEST(calls==(mode==0UL ? 1UL : count));
  FD_TEST(hits==(mode==0UL ? count-1UL : 0UL));
  char const * names[]={"exact_repeat","cold_cache_clear_control","fresh_canonical_S","two_colliding_keys_churn"};
  printf("{\"benchmark\":\"%s\",\"inputs\":%lu,\"verifications\":%lu,\"cache_hits\":%lu,\"seconds\":%.9f,\"ns_per_input\":%.3f,\"parser_resolver_pps\":%.3f}\n",
         names[mode],count,calls,hits,(double)elapsed/1e9,(double)elapsed/(double)count,(double)count*1e9/(double)elapsed);
}

int
main( int argc, char ** argv ) {
  fd_boot(&argc,&argv);
  FD_TEST(fd_sha512_new(sha));
  for( ulong j=0UL; j<32UL; j++ ) test_seed[j]=(uchar)(0xa0UL+j);
  fd_ed25519_public_from_private(leader.uc,test_seed,sha);
  fd_metrics_register(fd_metrics_new(metric_mem,0UL));
  setup();
  check_verification_key(); check_only_equation_failures(); check_repeat_at_capacity();
  for( ulong mode=0UL; mode<4UL; mode++ ) benchmark(mode,mode ? 32768UL : 131072UL);
  printf("{\"status\":\"PASS_NATIVE_INVALID_VERDICT_CACHE\",\"exact_key_bytes\":%lu,\"entries\":%lu,\"cache_bytes\":%lu,\"forced_bucket_collision_valid_controls\":%lu,\"non_equation_failures_not_cached\":4,\"no_network\":true}\n",
         sizeof(invalid_sig_key_t),INVALID_SIG_CACHE_CNT,sizeof(ctxs[0].resolver->invalid_sig_cache)+sizeof(ctxs[0].resolver->invalid_sig_valid),equality_controls);
  fd_halt(); return 0;
}
