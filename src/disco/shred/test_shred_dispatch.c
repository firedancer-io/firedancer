/* Native regression of the actual tile callbacks and resolver.  All signing
   uses a public, deterministic TEST seed.  No sockets, live keys or blocks. */
#define _GNU_SOURCE
#include "../../ballet/ed25519/fd_ed25519.h"
#include "../../ballet/ed25519/fd_curve25519.h"
static ulong verify_calls;
static int verify_result;
static int
observe_verify( uchar const * msg, ulong sz, uchar const * sig, uchar const * pub,
                fd_sha512_t * sha, fd_ed25519_cache_t * cache ) {
  verify_calls++;
  verify_result = fd_ed25519_verify_cached( msg, sz, sig, pub, sha, cache );
  return verify_result;
}
#define fd_ed25519_verify_cached observe_verify
#include "fd_fec_resolver.c"
#undef fd_ed25519_verify_cached
#include "fd_shred_tile.c"
#include "../../app/firedancer/callbacks.c"
#include "../../app/firedancer/topology.c"
#include "../topo/fd_topob.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/resource.h>

#define TILES 10UL
#define DEPTH 2UL
#define SETS (DEPTH+2UL)
#define SLOT 1000000UL
#define VERSION 15396U
#define SNAP_CAP (2UL<<20)

static fd_shred_ctx_t ctxs[TILES];
static fd_fec_set_t pool[TILES][SETS];
static void * resolver_mem[TILES];
static fd_stake_ci_t stake;
static fd_shredder_t maker[1];
static fd_fec_set_t made[1];
static uchar payload[FD_SHREDDER_CHAINED_FEC_SET_PAYLOAD_SZ];
static fd_sha512_t sha[1];
static uchar test_seed[32]; /* Deliberately public regression seed, never a live identity. */
static fd_pubkey_t leader;
static fd_rnonce_ss_t nonce_secret;
static uchar metric_mem[FD_METRICS_FOOTPRINT(0)] __attribute__((aligned(FD_METRICS_ALIGN)));
static fd_topo_t topology;
static uchar * key_memory;
static ulong key_page_sz, key_wksp;
static uchar packet[FD_NET_MTU] __attribute__((aligned(64)));
static uchar before[SNAP_CAP], after[SNAP_CAP];
static fd_epoch_leaders_t schedule;
static uint schedule_idx[512];
static ulong hist[TILES];
static ulong malformed_cases, sibling_cases, repaired_cases, equivocation_cases, completions;
static uint control_fec[TILES][DEPTH];
static ulong control_salt[TILES][DEPTH];

static void
append_snapshot( uchar * out, ulong * used, void const * in, ulong sz ) {
  FD_TEST( sz<=SNAP_CAP-*used );
  memcpy( out+*used, in, sz );
  *used+=sz;
}

/* Authenticated contexts (including Merkle state), all set buffers, membership,
   ordering and spare counts are byte compared.  Unauthenticated spare Merkle
   scratch, signature cache, verifier credits and metrics are allowed to change. */
static ulong
snapshot( ulong tile, uchar * out ) {
  fd_fec_resolver_t const * r=ctxs[tile].resolver;
  ulong n=0UL;
#define APP(p,s) append_snapshot( out, &n, (p), (s) )
  APP( &r->free_list_cnt, sizeof(r->free_list_cnt) );
  APP( r->ctx_map, ctx_map_footprint(ctx_map_chain_cnt_est(r->depth)) );
  APP( r->ctx_treap, sizeof(r->ctx_treap) );
  APP( r->free_list, sizeof(r->free_list) );
  APP( r->complete_list, sizeof(r->complete_list) );
  APP( r->done_map, done_map_footprint(done_map_chain_cnt_est(r->done_depth)) );
  APP( done_pool_leave(r->done_pool), done_pool_footprint(r->done_depth) );
  APP( r->done_heap, sizeof(r->done_heap) );
  for( ulong i=0UL; i<SETS; i++ ) APP( &r->ctx_pool[i].free_next, sizeof(r->ctx_pool[i].free_next) );
  for( ctx_treap_fwd_iter_t it=ctx_treap_fwd_iter_init(r->ctx_treap,r->ctx_pool);
       !ctx_treap_fwd_iter_done(it); it=ctx_treap_fwd_iter_next(it,r->ctx_pool) ) {
    set_ctx_t const * c=ctx_treap_fwd_iter_ele_const(it,r->ctx_pool);
    FD_TEST( ctx_map_ele_query_const(r->ctx_map,&c->sig,NULL,r->ctx_pool)==c );
    APP( c, sizeof(*c) );
  }
  APP( pool[tile], sizeof(pool[tile]) );
#undef APP
  return n;
}

static void
reset_resolvers( void ) {
  for( ulong i=0UL; i<TILES; i++ ) {
    memset( pool[i], 0, sizeof(pool[i]) );
    ulong footprint=fd_fec_resolver_footprint(DEPTH,1UL,1UL,128UL);
    if( !resolver_mem[i] ) FD_TEST( !posix_memalign(&resolver_mem[i],fd_fec_resolver_align(),footprint) );
    memset( resolver_mem[i], 0, footprint );
    ctxs[i].resolver=fd_fec_resolver_join(fd_fec_resolver_new(resolver_mem[i],DEPTH,1UL,1UL,128UL,2048UL,pool[i],99UL+i));
    FD_TEST( ctxs[i].resolver && !ctxs[i].resolver->bypass_verify );
    fd_fec_resolver_set_shred_version(ctxs[i].resolver,VERSION);
    fd_fec_resolver_advance_slot_old(ctxs[i].resolver,SLOT-1UL);
  }
}

static void
setup( void ) {
  /* Real object constructor, not a per-tile random seed.  Only the object ID
     goes into props.  Stack/heap-backed local memory uses NO hugepages. */
  FD_TEST(fd_topob_new(&topology,"owner_test"));
  fd_topob_wksp(&topology,"tile");
  for( ulong i=0UL; i<TILES; i++ ) fd_topob_tile(&topology,"shred","tile","tile",0UL,0,0,0);
  /* Exercise the production builder, including all ten READ_ONLY joins. */
  fd_topo_obj_t * obj=setup_topo_shred_key(&topology);
  key_wksp=obj->wksp_id;
  fd_topo_wksp_t * wk=&topology.workspaces[key_wksp];
  FD_TEST(wk->core_dump_level==FD_TOPO_CORE_DUMP_LEVEL_NEVER);
  obj->offset=16UL;
  key_page_sz=(ulong)sysconf(_SC_PAGESIZE);
  key_memory=mmap(NULL,key_page_sz,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
  FD_TEST(key_memory!=MAP_FAILED && !madvise(key_memory,key_page_sz,MADV_DONTDUMP));
  wk->wksp=(fd_wksp_t *)key_memory;
  FD_TEST(fd_obj_cb_shred_key.footprint(&topology,obj)==16UL);
  FD_TEST(fd_obj_cb_shred_key.align(&topology,obj)<=16UL);
  fd_topo_obj_callbacks_t * callbacks[]={ &fd_obj_cb_shred_key, NULL };
  fd_topo_wksp_new(&topology,wk,callbacks);
  FD_TEST(!mprotect(key_memory,key_page_sz,PROT_READ));
  FD_TEST(fd_pod_query_ulong(topology.props,"shred_key",ULONG_MAX)==obj->id);
  for( ulong i=0UL; i<TILES; i++ ) {
    fd_shred_ctx_t * c=&ctxs[i];
    c->round_robin_id=i; c->round_robin_cnt=TILES;
    c->dispatch_key=join_dispatch_key(&topology);
    FD_TEST(c->dispatch_key==join_dispatch_key(&topology));
    fd_topo_tile_t const * tile=&topology.tiles[i];
    ulong matches=0UL;
    for( ulong j=0UL; j<tile->uses_obj_cnt; j++ ) if( tile->uses_obj_id[j]==obj->id ) {
      FD_TEST(tile->uses_obj_mode[j]==FD_SHMEM_JOIN_MODE_READ_ONLY); matches++;
    }
    FD_TEST(matches==1UL);
    c->in_kind[0]=IN_KIND_NET;
    c->shred_limit=32768UL;
    c->prev_max_shred_idx=c->current_max_shred_idx=c->next_max_shred_idx=32768UL;
    c->next_max_shred_idx_start_slot=ULONG_MAX;
    c->repair_out_idx=c->shred_out_idx=ULONG_MAX;
    c->new_root=SLOT-1UL; c->slot_max=2048UL;
    c->repair_nonce_ss[0]=nonce_secret;
    c->shredder=maker; c->fec_sets=pool[i]; c->stake_ci=&stake;
    fd_histf_join(fd_histf_new(c->metrics->add_shred_timing,1UL,1000000000UL));
  }
  /* A real schedule lookup in after_frag, with a distinct receiver identity. */
  schedule=(fd_epoch_leaders_t){ .slot0=SLOT-1UL, .slot_cnt=2048UL,
    .pub=&leader, .pub_cnt=1UL, .sched=schedule_idx, .sched_cnt=512UL };
  stake.epoch_info[0].start_slot=SLOT-1UL;
  stake.epoch_info[0].slot_cnt=2048UL;
  stake.epoch_info[0].lsched=&schedule;
  FD_TEST(fd_shredder_new(maker));
  fd_shredder_set_shred_version(maker,VERSION);
  reset_resolvers();
}

/* Original production shredder, real proofs and canonical invalid signatures.
   Valid controls sign only synthetic test bytes with a public fixture seed. */
static fd_shred_t const *
make_set( ulong slot, uint fec, ulong salt, int valid ) {
  FD_TEST(fd_shredder_new(maker)); fd_shredder_set_shred_version(maker,VERSION);
  if( fec ) FD_TEST(fd_shredder_skip_batch(maker,((ulong)fec/32UL)*sizeof(payload),slot,0));
  for( ulong j=0UL; j<sizeof(payload); j++ ) payload[j]=(uchar)fd_ulong_hash(j^salt);
  fd_entry_batch_meta_t meta={.parent_offset=1U};
  uchar chain[32]={0};
  FD_TEST(fd_shredder_init_batch(maker,payload,sizeof(payload),slot,&meta));
  FD_TEST(fd_shredder_next_fec_set(maker,made,chain));
  FD_TEST(fd_shredder_fini_batch(maker));
  uchar signature[64]={0}; signature[0]=0x58; memset(signature+1,0x66,31UL);
  memcpy(signature+32,&slot,8UL); memcpy(signature+40,&salt,8UL);
  if( valid ) fd_ed25519_sign(signature,chain,32UL,leader.uc,test_seed,sha);
  else {
    fd_ed25519_point_t point[1]; uchar encoded[32];
    FD_TEST(fd_ed25519_point_frombytes(point,signature));
    FD_TEST(!fd_ed25519_affine_is_small_order(point));
    fd_ed25519_point_tobytes(encoded,point); FD_TEST(!memcmp(encoded,signature,32UL));
    FD_TEST(fd_curve25519_scalar_validate(signature+32));
    FD_TEST(fd_ed25519_verify(chain,32UL,signature,leader.uc,sha)==FD_ED25519_ERR_MSG);
  }
  for( ulong j=0UL; j<32UL; j++ ) {
    memcpy(made->data_shreds[j].s->signature,signature,64UL);
    memcpy(made->parity_shreds[j].s->signature,signature,64UL);
  }
  FD_TEST(made->data_shreds[0].s->slot==slot && made->data_shreds[0].s->fec_set_idx==fec);
  return made->data_shreds[0].s;
}

/* Feed net metadata and bytes through production before/during/after callbacks
   on all ten tiles.  No alternative dispatch implementation is used here. */
static ulong
receive_at( uchar * frame, ulong payload_sz, ulong proto, int run_after, int expected_rv ) {
  ulong sz=42UL+payload_sz;
  fd_udp_hdr_t * udp=(fd_udp_hdr_t *)(frame+42UL-sizeof(fd_udp_hdr_t));
  udp->net_len=fd_ushort_bswap((ushort)(8UL+payload_sz));
  ulong sig=fd_disco_netmux_sig(0U,0U,0U,proto,42UL);
  ulong owner=ULONG_MAX, owners=0UL, parses=0UL;
  for( ulong i=0UL; i<TILES; i++ ) {
    fd_shred_ctx_t * c=&ctxs[i];
    c->in[0].net_rx=(fd_net_rx_bounds_t){ .base=(ulong)frame, .pkt_lo=(ulong)frame, .pkt_hi=(ulong)frame+sz };
    FD_TEST(before_frag(c,0UL,0UL,sig)==0);
    during_frag(c,0UL,0UL,sig,0UL,sz,0UL);
    parses+=(ulong)c->parse_failed;
    if( !c->skip_frag ) {
      owners++; owner=i;
      FD_TEST(c->shred_buffer_sz==payload_sz && !memcmp(c->shred_buffer,frame+42UL,payload_sz));
    }
    if( run_after ) {
      ulong idx=(ulong)(expected_rv+FD_FEC_RESOLVER_ADD_SHRED_RETVAL_OFF+FD_SHRED_ADD_SHRED_EXTRA_RETVAL_CNT);
      ulong old=c->metrics->shred_processing_result[idx];
      after_frag(c,0UL,0UL,sig,sz,0UL,0UL,NULL);
      if( !c->skip_frag ) FD_TEST(c->metrics->shred_processing_result[idx]==old+1UL);
    }
  }
  FD_TEST(owners==1UL || (owners==0UL && parses==1UL));
  return owner;
}

static ulong
receive( fd_shred_t const * s, ulong proto, int run_after, int expected ) {
  ulong sz=fd_shred_sz(s); memcpy(packet+42UL,s,sz);
  if( proto==DST_PROTO_REPAIR ) {
    uint nonce=fd_rnonce_ss_compute(&nonce_secret,1,s->slot,s->idx,fd_log_wallclock());
    memcpy(packet+42UL+sz,&nonce,4UL); sz+=4UL;
  }
  return receive_at(packet,sz,proto,run_after,expected);
}

static void
check_siblings_equivocation_repair( void ) {
  fd_shred_t const * s=make_set(SLOT,0U,1UL,1);
  ulong owner=receive(s,DST_PROTO_SHRED,1,FD_FEC_RESOLVER_SHRED_OKAY);
  ulong old_sig_owner=fd_ulong_load_8(s->signature)%TILES;
  for( ulong j=0UL; j<64UL; j++ ) {
    s=j<32UL ? made->data_shreds[j].s : made->parity_shreds[j-32UL].s;
    FD_TEST(receive(s,DST_PROTO_SHRED,0,0)==owner); sibling_cases++;
  }
  FD_TEST(receive(made->parity_shreds[0].s,DST_PROTO_REPAIR,1,FD_FEC_RESOLVER_SHRED_OKAY)==owner); repaired_cases++;
  FD_TEST(!ctxs[owner].metrics->bad_nonce);
  /* An invalid alternate signature for an ACTIVE tuple reaches equation
     verification on the SAME resolver and cannot disturb the valid context. */
  s=make_set(SLOT,0U,3UL,0);
  ulong calls=verify_calls, n=snapshot(owner,before);
  FD_TEST(receive(s,DST_PROTO_REPAIR,1,FD_FEC_RESOLVER_SHRED_REJECTED)==owner);
  FD_TEST(verify_calls==calls+1UL && verify_result==FD_ED25519_ERR_MSG);
  FD_TEST(snapshot(owner,after)==n && !memcmp(before,after,n)); repaired_cases++;
  /* Authenticated equivocation uses a DIFFERENT root/signature for same tuple.
     Select a public fixture that would split owners under the old dispatch. */
  for( ulong salt=2UL; ; salt++ ) {
    FD_TEST(salt<128UL);
    s=make_set(SLOT,0U,salt,1);
    if( fd_ulong_load_8(s->signature)%TILES!=old_sig_owner ) break;
  }
  calls=verify_calls;
  FD_TEST(receive(s,DST_PROTO_SHRED,1,FD_FEC_RESOLVER_SHRED_EQUIVOC)==owner);
  FD_TEST(verify_calls==calls+1UL && verify_result==FD_ED25519_SUCCESS); equivocation_cases++;
  s=make_set(SLOT,0U,3UL,0);
  /* Every one-byte change in S preserves the owner, including canonical S. */
  for( ulong j=32UL; j<64UL; j++ ) {
    uchar save=made->data_shreds[0].s->signature[j];
    made->data_shreds[0].s->signature[j]^=1U;
    FD_TEST(receive(s,DST_PROTO_SHRED,0,0)==owner);
    made->data_shreds[0].s->signature[j]=save;
  }
}

static void
fill_pools( void ) {
  reset_resolvers(); ulong filled[TILES]={0}, count=0UL;
  for( ulong j=0UL; count<TILES*DEPTH; j++ ) {
    fd_shred_t const * s=make_set(SLOT,(uint)(32UL*j),j+1UL,1);
    ulong owner=receive(s,DST_PROTO_SHRED,0,0);
    if( filled[owner]==DEPTH ) continue;
    FD_TEST(receive(s,DST_PROTO_SHRED,1,FD_FEC_RESOLVER_SHRED_OKAY)==owner);
    control_fec[owner][filled[owner]]=s->fec_set_idx;
    control_salt[owner][filled[owner]]=j+1UL;
    filled[owner]++; count++;
  }
  for( ulong i=0UL; i<TILES; i++ ) {
    FD_TEST(ctx_treap_ele_cnt(ctxs[i].resolver->ctx_treap)==DEPTH);
    FD_TEST(ctxs[i].resolver->free_list_cnt==1UL);
  }
}

static void
check_pressure( void ) {
  fill_pools();
  ulong initial=FD_MCNT_GET(SHRED,INITIAL_REJECTED), calls=verify_calls;
  for( ulong j=0UL; j<32768UL; j++ ) {
    fd_shred_t const * s=make_set(SLOT+1UL+j/1024UL,(uint)(32UL*(j%1024UL)),j+1UL,0);
    FD_TEST(fd_ulong_load_8(s->signature)%TILES==2UL); /* Old steering control. */
    ulong owner=receive(s,DST_PROTO_SHRED,0,0); hist[owner]++;
    fd_fec_resolver_t * r=ctxs[owner].resolver;
    slot_fec_pair_t pair={.slot=s->slot,.fec_idx=s->fec_set_idx};
    FD_TEST(!ctx_treap_ele_query_const(r->ctx_treap,&pair,r->ctx_pool));
    FD_TEST(!done_map_ele_query_const(r->done_map,&pair,NULL,r->done_pool));
    ulong n=snapshot(owner,before), old=verify_calls;
    FD_TEST(receive(s,DST_PROTO_SHRED,1,FD_FEC_RESOLVER_SHRED_REJECTED)==owner);
    FD_TEST(verify_calls==old+1UL && verify_result==FD_ED25519_ERR_MSG);
    FD_TEST(snapshot(owner,after)==n && !memcmp(before,after,n));
  }
  FD_TEST(verify_calls==calls+32768UL && FD_MCNT_GET(SHRED,INITIAL_REJECTED)==initial+32768UL);
  FD_TEST(!FD_MCNT_GET(SHRED,FEC_INCOMPLETE_EVICTED));
  for( ulong i=0UL; i<TILES; i++ ) FD_TEST(hist[i]>2600UL && hist[i]<4000UL);
  /* LIMITATION control: fresh canonical S, same tuple, same tile, real
     equation work on every emission. No negative verdict cache is implied. */
  ulong fixed_owner=ULONG_MAX;
  fd_shred_t const * fixed=make_set(SLOT+64UL,0U,1UL,0);
  uchar tree[FD_BMTREE_COMMIT_FOOTPRINT(FD_SHRED_MERKLE_LAYER_CNT)] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  fd_bmtree_node_t fixed_root;
  FD_TEST(fd_shred_merkle_root(fixed,tree,&fixed_root));
  for( ulong j=0UL; j<1024UL; j++ ) {
    ulong ordinal=j+1UL;
    memcpy(made->data_shreds[0].s->signature+40,&ordinal,8UL);
    FD_TEST(fd_curve25519_scalar_validate(fixed->signature+32));
    FD_TEST(fd_ed25519_verify(fixed_root.hash,32UL,fixed->signature,leader.uc,sha)==FD_ED25519_ERR_MSG);
    ulong old=verify_calls;
    ulong owner=receive(fixed,DST_PROTO_SHRED,1,FD_FEC_RESOLVER_SHRED_REJECTED);
    if( !j ) fixed_owner=owner;
    FD_TEST(owner==fixed_owner && verify_calls==old+1UL && verify_result==FD_ED25519_ERR_MSG);
  }
  /* Every legitimate incomplete set still completes through the callback
     after pressure, with original data recovered byte for byte. */
  for( ulong tile=0UL; tile<TILES; tile++ ) for( ulong k=0UL; k<DEPTH; k++ ) {
    make_set(SLOT,control_fec[tile][k],control_salt[tile][k],1);
    for( ulong j=0UL; j<31UL; j++ ) {
      int expected=j==30UL ? FD_FEC_RESOLVER_SHRED_COMPLETES : FD_FEC_RESOLVER_SHRED_OKAY;
      FD_TEST(receive(made->parity_shreds[j].s,DST_PROTO_REPAIR,1,expected)==tile);
    }
    /* The just-completed buffer is on complete_list; inspect actual bytes. */
    fd_fec_resolver_t * r=ctxs[tile].resolver;
    set_ctx_t const * c=ctx_list_ele_peek_tail_const(r->complete_list,r->ctx_pool);
    FD_TEST(c);
    fd_fec_set_t const * set=c->set;
    for( ulong j=0UL; j<32UL; j++ )
      FD_TEST(!memcmp(set->data_shreds[j].b,made->data_shreds[j].b,FD_SHRED_MIN_SZ));
    completions++;
  }
  FD_TEST(!FD_MCNT_GET(SHRED,FEC_INCOMPLETE_EVICTED));
  printf("{\"constant_R_distinct_tuples\":32768,\"old_owner2\":32768,\"keyed_histogram\":[");
  for( ulong i=0UL; i<TILES; i++ ) printf("%s%lu",i?",":"",hist[i]);
  printf("],\"pool_byte_equal\":32768,\"fixed_tuple_fresh_S\":1024,\"fixed_tuple_owner\":%lu,\"equation_work_each\":true}\n",fixed_owner);
}

static void
check_short_bounds( void ) {
  long page=sysconf(_SC_PAGESIZE); FD_TEST(page>0);
  uchar * mem=mmap(NULL,(ulong)page*3UL,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
  FD_TEST(mem!=MAP_FAILED && !mprotect(mem+(ulong)page,(ulong)page,PROT_READ|PROT_WRITE));
  /* Each payload ends EXACTLY at the inaccessible page.  The callback/parser
     cannot speculatively read signature, tuple or hash bytes past its bound. */
  uchar prefixes[3][128]={{0}};
  make_set(SLOT,0U,9UL,0);
  memcpy(prefixes[1],made->data_shreds[0].b,128UL);
  memcpy(prefixes[2],made->parity_shreds[0].b,128UL);
  for( ulong kind=0UL; kind<3UL; kind++ ) for( ulong n=0UL; n<128UL; n++ ) {
    uchar * frame=mem+2UL*(ulong)page-42UL-n;
    memset(frame,0,42UL+n); memcpy(frame+42UL,prefixes[kind],n);
    FD_TEST(receive_at(frame,n,DST_PROTO_SHRED,1,FD_FEC_RESOLVER_SHRED_REJECTED)==ULONG_MAX);
    malformed_cases++;
  }
  FD_TEST(!munmap(mem,(ulong)page*3UL));
}

static void
check_missing_key( void ) {
  for( int mode=0; mode<3; mode++ ) {
    pid_t pid=fork(); FD_TEST(pid>=0);
    if( !pid ) {
      /* Failures must not produce a core or leak the key. */
      struct rlimit no_core={0,0}; FD_TEST(!setrlimit(RLIMIT_CORE,&no_core));
      if( mode==0 ) FD_TEST(!fd_pod_remove(topology.props,"shred_key"));
      if( mode==1 ) { FD_TEST(!fd_pod_remove(topology.props,"shred_key")); FD_TEST(fd_pod_insert_ulong(topology.props,"shred_key",topology.obj_cnt)); }
      if( mode==2 ) topology.workspaces[key_wksp].wksp=NULL;
      (void)join_dispatch_key(&topology); _exit(0);
    }
    int status; FD_TEST(waitpid(pid,&status,0)==pid);
    FD_TEST(WIFEXITED(status) && WEXITSTATUS(status)==1);
  }
}

int
main( int argc, char ** argv ) {
  fd_boot(&argc,&argv);
  FD_TEST(fd_sha512_new(sha));
  for( ulong j=0UL; j<32UL; j++ ) test_seed[j]=(uchar)(0xa0UL+j);
  fd_ed25519_public_from_private(leader.uc,test_seed,sha);
  fd_metrics_register(fd_metrics_new(metric_mem,0UL));
  setup(); check_missing_key(); check_short_bounds();
  check_siblings_equivocation_repair(); check_pressure();
  printf("{\"callback_path\":\"before_frag/during_frag/after_frag/resolver\",\"data_code_siblings\":%lu,\"repair\":%lu,\"authenticated_equivocation\":%lu,\"guard_page_malformed\":%lu,\"missing_key_failures\":3,\"shared_key_tiles\":10,\"legitimate_completions\":%lu,\"evictions\":0}\n",sibling_cases,repaired_cases,equivocation_cases,malformed_cases,completions);
  for( ulong i=0UL; i<TILES; i++ ) free(resolver_mem[i]);
  FD_TEST(!mprotect(key_memory,key_page_sz,PROT_READ|PROT_WRITE));
  fd_memzero_explicit(key_memory,key_page_sz); FD_TEST(!munmap(key_memory,key_page_sz));
  FD_LOG_NOTICE(("pass")); fd_halt(); return 0;
}
