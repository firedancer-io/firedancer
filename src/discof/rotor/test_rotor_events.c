#include "fd_rotor.h"
#include <stdlib.h>

static fd_hash_t const zero = {0};
static fd_hash_t
hash( ulong n ) {
  fd_hash_t h={0};
  h.ul[0]=n; h.ul[1]=0xa5UL; h.ul[3]=n+1UL;
  return h;
}

static fd_rotor_t *
new_rotor( ulong jobs ) {
  fd_rotor_config_t c=fd_rotor_config_default();
  c.block_max=16UL; c.max_shreds=256UL; c.shred_request_max=jobs;
  c.seed_window=4UL; c.turbine_grace=100L; c.highest_delay=250L; c.retry_delay=100L;
  void * mem=aligned_alloc(fd_rotor_align(),fd_rotor_footprint(&c));
  FD_TEST(mem);
  fd_rotor_t * r=fd_rotor_join(fd_rotor_new(mem,&c,123UL,NULL));
  FD_TEST(r);
  fd_hash_t root=hash(1UL);
  FD_TEST(fd_rotor_frag_snapshot(r,1UL,&root)==FD_ROTOR_ACCEPT);
  FD_TEST(!fd_rotor_verify(r));
  return r;
}

static void
shred( fd_rotor_t * r, ulong slot, uint idx, ulong mr, int end, int repair, long now ) {
  fd_rotor_shred_t e={ .kind=FD_ROTOR_SHRED_DATA, .src=repair ? FD_ROTOR_SRC_REPAIR : FD_ROTOR_SRC_TURBINE,
    .slot=slot, .idx=idx, .merkle_root=hash(mr), .slot_complete=end };
  FD_TEST(fd_rotor_frag_shred(r,&e,now)==FD_ROTOR_ACCEPT);
  FD_TEST(!fd_rotor_verify(r));
}

static void
complete( fd_rotor_t * r, ulong slot, uint idx, ulong mr, int end ) {
  fd_rotor_shred_t e={ .kind=FD_ROTOR_SHRED_COMPLETE, .slot=slot, .idx=idx,
    .merkle_root=hash(mr), .slot_complete=end, .data_complete=1 };
  FD_TEST(fd_rotor_frag_shred(r,&e,50L)==FD_ROTOR_ACCEPT);
  FD_TEST(!fd_rotor_verify(r));
}

static void
notar( fd_rotor_t * r, ulong slot, ulong id ) {
  fd_hash_t h=hash(id);
  FD_TEST(fd_rotor_frag_votor(r,slot,&h,0,0L)==FD_ROTOR_ACCEPT);
  FD_TEST(!fd_rotor_verify(r));
}

static void
parent( fd_rotor_t * r, ulong slot, ulong id, uint count, ulong pslot, ulong pid ) {
  fd_rotor_net_t e={ .kind=AG_REPAIR_KIND_PARENT_FEC_COUNT, .slot=slot, .block_id=hash(id),
    .fec_count=count, .parent_slot=pslot, .parent_id=hash(pid) };
  FD_TEST(fd_rotor_frag_net(r,&e,0L)==FD_ROTOR_ACCEPT);
  FD_TEST(!fd_rotor_verify(r));
}

static void
root( fd_rotor_t * r, ulong slot, ulong id, uint idx, ulong mr ) {
  fd_hash_t h=hash(mr);
  fd_rotor_net_t e={ .kind=AG_REPAIR_KIND_FEC_ROOT, .slot=slot, .block_id=hash(id), .fec_idx=idx };
  memcpy(e.root_prefix,h.uc,FD_SHRED_MERKLE_NODE_SZ);
  FD_TEST(fd_rotor_frag_net(r,&e,0L)==FD_ROTOR_ACCEPT);
  FD_TEST(!fd_rotor_verify(r));
}

static void
crank( fd_rotor_t * r, long now ) {
  fd_rotor_advance(r,now,0UL,10000UL);
  FD_TEST(!fd_rotor_verify(r));
}

static ulong
requests( fd_rotor_t * r, long now, fd_rotor_request_t * out ) {
  ulong n=0;
  fd_rotor_token_t token;
  while( fd_rotor_request_next(r,now,10000UL,out+n,&token) ) {
    FD_TEST(n<1023UL);
    n++;
    fd_rotor_request_sent(r,token,1,now);
  }
  FD_TEST(!fd_rotor_verify(r));
  return n;
}

static int
has( fd_rotor_request_t * req, ulong n, uint kind, ulong slot, uint idx ) {
  for( ulong i=0; i<n; i++ ) if( req[i].kind==kind && req[i].slot==slot && req[i].idx==idx ) return 1;
  return 0;
}

static void
test_sparse_deadlines( void ) {
  fd_rotor_t * r=new_rotor(512UL);
  shred(r,10UL,70U,100UL,0,0,0L);
  crank(r,0L);
  fd_rotor_stats_t s;
  fd_rotor_stats(r,&s);
  FD_TEST(s.fecs==1UL);
  fd_rotor_request_t req[1024];
  ulong n=requests(r,0L,req);
  FD_TEST(n==2UL);
  FD_TEST(has(req,n,FD_REPAIR_KIND_SHRED,10UL,0U));
  FD_TEST(has(req,n,FD_REPAIR_KIND_ORPHAN,10UL,0U));
  shred(r,10UL,70U,100UL,0,0,50L); /* duplicates cannot postpone due=100 */
  crank(r,50L);
  FD_TEST(!requests(r,99L,req));
  n=requests(r,100L,req);
  FD_TEST(has(req,n,FD_REPAIR_KIND_SHRED,10UL,32U));
  for( uint idx=64; idx<96; idx++ ) if( idx!=70U ) FD_TEST(has(req,n,FD_REPAIR_KIND_SHRED,10UL,idx));
  shred(r,10UL,191U,101UL,1,1,110L); /* highest response: fill tail immediately */
  crank(r,110L);
  n=requests(r,110L,req);
  FD_TEST(has(req,n,FD_REPAIR_KIND_SHRED,10UL,128U));
  for( uint idx=160U; idx<191U; idx++ ) FD_TEST(has(req,n,FD_REPAIR_KIND_SHRED,10UL,idx));
  fd_rotor_stats(r,&s);
  FD_TEST(s.fecs==2UL);
  n=requests(r,250L,req);
  for( ulong i=0; i<n; i++ ) FD_TEST(req[i].kind!=FD_REPAIR_KIND_HIGHEST_SHRED);
  free(fd_rotor_delete(fd_rotor_leave(r)));
}

static void
test_shared_completion_and_final( void ) {
  fd_rotor_t * r=new_rotor(512UL);
  shred(r,10UL,0U,100UL,0,0,0L);
  notar(r,10UL,10UL);
  parent(r,10UL,10UL,1U,1UL,1UL);
  root(r,10UL,10UL,0U,100UL);
  fd_rotor_fec_info_t a,b;
  fd_hash_t id=hash(10UL);
  FD_TEST(fd_rotor_fec_query(r,10UL,&zero,0U,&a));
  FD_TEST(fd_rotor_fec_query(r,10UL,&id,0U,&b));
  FD_TEST(a.owner && !b.owner && a.received==1U && b.received==1U);
  shred(r,10UL,7U,100UL,0,1,5L);
  FD_TEST(fd_rotor_fec_query(r,10UL,&id,0U,&b) && b.received==129U);
  complete(r,10UL,0U,100UL,1);
  complete(r,10UL,0U,100UL,1);
  fd_rotor_block_info_t bi;
  FD_TEST(fd_rotor_block_query(r,10UL,&id,&bi) && bi.recovered_cnt==30U && bi.delivered_shreds==32U);
  fd_rotor_delivery_t d;
  FD_TEST(fd_rotor_delivery_next(r,&d) && fd_hash_eq(&d.block_id,&id));
  FD_TEST(fd_rotor_frag_votor(r,10UL,&id,1,60L)==FD_ROTOR_AGAIN);
  fd_rotor_delivery_pop(r,60L);
  /* Late root attachment adopts existing completion without another completion event. */
  notar(r,10UL,11UL); parent(r,10UL,11UL,1U,1UL,1UL); root(r,10UL,11UL,0U,100UL);
  fd_hash_t winner=hash(11UL);
  FD_TEST(fd_rotor_block_query(r,10UL,&winner,&bi) && bi.delivered_shreds==32U);
  FD_TEST(fd_rotor_frag_votor(r,10UL,&winner,1,70L)==FD_ROTOR_ACCEPT);
  FD_TEST(fd_rotor_fec_query(r,10UL,&winner,0U,&b) && b.owner && b.received==UINT_MAX);
  FD_TEST(!fd_rotor_block_query(r,10UL,&id,&bi));
  FD_TEST(!fd_rotor_verify(r));
  FD_TEST(fd_rotor_delivery_next(r,&d) && fd_hash_eq(&d.block_id,&winner));
  fd_rotor_delivery_pop(r,80L);
  FD_TEST(!fd_rotor_delivery_next(r,&d));
  FD_TEST(fd_rotor_frag_replay_root(r,10UL,&winner,90L)==FD_ROTOR_ACCEPT);
  FD_TEST(!fd_rotor_verify(r));
  fd_rotor_stats_t s; fd_rotor_stats(r,&s); FD_TEST(s.blocks==1UL && !s.fecs);
  free(fd_rotor_delete(r));
}

static void
test_pressure_reservation_eviction( void ) {
  fd_rotor_t * r=new_rotor(2UL);
  notar(r,10UL,10UL); parent(r,10UL,10UL,2U,1UL,1UL); root(r,10UL,10UL,32U,100UL);
  crank(r,0L);
  fd_rotor_stats_t s; fd_rotor_stats(r,&s);
  FD_TEST(s.shred_requests==2UL && s.shred_dropped==30UL && s.fecs==1UL);
  fd_rotor_request_t req[1024]; fd_rotor_token_t t,other;
  FD_TEST(fd_rotor_request_next(r,0L,100UL,req,&t));
  FD_TEST(req[0].kind==AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID);
  FD_TEST(fd_rotor_request_next(r,0L,100UL,req,&other));
  FD_TEST(req[0].kind==AG_REPAIR_KIND_FEC_ROOT && req[0].idx==0U);
  fd_rotor_request_sent(r,other,1,0L);
  fd_rotor_request_sent(r,t,0,0L); /* no transport capacity: still immediately retryable */
  ulong n=requests(r,0L,req);
  FD_TEST(n==2UL);
  /* Accepted arrivals still update state while the queue is full. */
  shred(r,10UL,32U,100UL,0,1,10L);
  shred(r,10UL,33U,100UL,0,1,10L);
  requests(r,100L,req); /* lazily retire satisfied shred requests */
  fd_rotor_shred_t ev={ .kind=FD_ROTOR_SHRED_EVICTED, .slot=10UL, .idx=32U, .merkle_root=hash(100UL) };
  FD_TEST(fd_rotor_frag_shred(r,&ev,110L)==FD_ROTOR_ACCEPT);
  n=requests(r,110L,req);
  FD_TEST(has(req,n,AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID,10UL,32U));
  FD_TEST(has(req,n,AG_REPAIR_KIND_SHRED_FOR_BLOCK_ID,10UL,33U));
  FD_TEST(!fd_rotor_verify(r));
  free(fd_rotor_delete(r));
}

static void
test_ancestry_and_redelivery( void ) {
  fd_rotor_t * r=new_rotor(512UL);
  notar(r,11UL,11UL); parent(r,11UL,11UL,1U,10UL,10UL); root(r,11UL,11UL,0U,111UL);
  complete(r,11UL,0U,111UL,1);
  fd_rotor_delivery_t d;
  FD_TEST(!fd_rotor_delivery_next(r,&d));
  crank(r,0L); /* materializes exact missing parent with its own metadata job */
  fd_rotor_request_t req[1024];
  ulong n=requests(r,0L,req);
  FD_TEST(has(req,n,AG_REPAIR_KIND_PARENT_FEC_COUNT,10UL,0U));
  parent(r,10UL,10UL,1U,1UL,1UL); root(r,10UL,10UL,0U,110UL);
  complete(r,10UL,0U,110UL,1);
  FD_TEST(fd_rotor_delivery_next(r,&d) && d.slot==10UL);
  fd_rotor_delivery_pop(r,1L);
  fd_rotor_frag_replay_missing(r);
  FD_TEST(fd_rotor_delivery_next(r,&d) && d.slot==10UL && d.redelivery);
  fd_rotor_delivery_pop(r,2L);
  FD_TEST(fd_rotor_delivery_next(r,&d) && d.slot==11UL && !d.redelivery);
  fd_hash_t id=hash(11UL);
  FD_TEST(fd_rotor_frag_replay_root(r,11UL,&id,3L)==FD_ROTOR_ACCEPT);
  fd_rotor_stats_t s; fd_rotor_stats(r,&s); FD_TEST(s.blocks==3UL);
  fd_rotor_delivery_pop(r,4L);
  fd_rotor_stats(r,&s); FD_TEST(s.blocks==1UL && !s.fecs);
  FD_TEST(!fd_rotor_verify(r));
  free(fd_rotor_delete(r));
}

static void
test_late_marker_cancel_and_rekey( void ) {
  fd_rotor_t * r=new_rotor(512UL);
  shred(r,10UL,0U,100UL,0,0,0L);
  complete(r,10UL,0U,100UL,1);
  fd_rotor_block_info_t b;
  FD_TEST(fd_rotor_block_query(r,10UL,&zero,&b) && fd_hash_check_zero(&b.block_id));
  fd_rotor_shred_t e={ .kind=FD_ROTOR_SHRED_INVALID, .slot=10UL };
  FD_TEST(fd_rotor_frag_shred(r,&e,0L)==FD_ROTOR_ACCEPT);
  e=(fd_rotor_shred_t){ .kind=FD_ROTOR_SHRED_DATA, .slot=10UL, .idx=0U, .merkle_root=hash(100UL),
    .has_parent=1, .parent_slot=1UL, .parent_id=hash(1UL) };
  FD_TEST(fd_rotor_frag_shred(r,&e,0L)==FD_ROTOR_ACCEPT);
  FD_TEST(fd_rotor_block_query(r,10UL,&zero,&b) && b.cancel && !fd_hash_check_zero(&b.block_id) && b.delivered_shreds==32U);
  crank(r,0L);
  fd_rotor_request_t req[1024]; FD_TEST(!requests(r,1000L,req));
  fd_rotor_delivery_t d; FD_TEST(fd_rotor_delivery_next(r,&d)); fd_rotor_delivery_pop(r,0L);
  FD_TEST(!fd_rotor_verify(r));
  free(fd_rotor_delete(r));
}

static void
test_seed_and_generation( void ) {
  fd_rotor_t * r=new_rotor(512UL);
  shred(r,20UL,0U,100UL,0,0,0L);
  fd_rotor_advance(r,0L,64UL,1000UL);
  fd_rotor_stats_t s; fd_rotor_stats(r,&s); FD_TEST(s.blocks==2UL);
  fd_rotor_request_t req[1024];
  ulong n=requests(r,0L,req);
  for( ulong slot=2; slot<=5; slot++ ) {
    FD_TEST(has(req,n,FD_REPAIR_KIND_SHRED,slot,0U));
    FD_TEST(has(req,n,FD_REPAIR_KIND_HIGHEST_SHRED,slot,0U));
  }
  /* Hold a signing token across pruning and pool reuse. */
  fd_rotor_token_t token;
  FD_TEST(fd_rotor_request_next(r,100L,1000UL,req,&token));
  notar(r,20UL,20UL);
  fd_hash_t id=hash(20UL);
  FD_TEST(fd_rotor_frag_votor(r,20UL,&id,1,100L)==FD_ROTOR_ACCEPT);
  fd_rotor_request_sent(r,token,1,100L);
  crank(r,100L);
  n=requests(r,1000L,req);
  for( ulong i=0; i<n; i++ ) if( req[i].slot==20UL ) FD_TEST(req[i].kind==AG_REPAIR_KIND_PARENT_FEC_COUNT);
  FD_TEST(!fd_rotor_verify(r));
  free(fd_rotor_delete(r));
}

static void
test_final_capacity_and_stale_tokens( void ) {
  fd_rotor_t * r=new_rotor(512UL);
  for( ulong id=10; id<17; id++ ) notar(r,10UL,id);
  crank(r,0L);
  fd_rotor_request_t req[1024]; fd_rotor_token_t token;
  FD_TEST(fd_rotor_request_next(r,0L,100UL,req,&token));
  fd_hash_t winner=hash(99UL);
  /* An unknown final can replace seven versions without an eighth slot. */
  FD_TEST(fd_rotor_frag_votor(r,10UL,&winner,1,0L)==FD_ROTOR_ACCEPT);
  notar(r,11UL,111UL); /* reuse released pool entries before old sign response */
  fd_rotor_request_sent(r,token,1,0L);
  fd_rotor_request_sent(r,token,1,0L); /* duplicate acknowledgment is harmless */
  crank(r,0L);
  ulong n=requests(r,0L,req);
  FD_TEST(n==2UL);
  for( ulong i=0; i<n; i++ ) {
    FD_TEST(req[i].kind==AG_REPAIR_KIND_PARENT_FEC_COUNT);
    if( req[i].slot==10UL ) FD_TEST(fd_hash_eq(&req[i].block_id,&winner));
  }
  fd_rotor_net_t late={ .kind=AG_REPAIR_KIND_PARENT_FEC_COUNT, .slot=10UL, .block_id=hash(10UL),
    .fec_count=1U, .parent_slot=1UL, .parent_id=hash(1UL) };
  FD_TEST(fd_rotor_frag_net(r,&late,0L)==FD_ROTOR_IGNORE);
  FD_TEST(!fd_rotor_verify(r));
  free(fd_rotor_delete(r));
}

static void
test_metadata_pressure( void ) {
  fd_rotor_t * r=new_rotor(2UL);
  /* Repeated finality/pruning accumulates lazy entries from old pool
     generations until metadata capacity is exhausted. */
  for( ulong slot=2; slot<230; slot++ ) {
    notar(r,slot,slot);
    crank(r,0L);
    fd_hash_t id=hash(slot);
    FD_TEST(fd_rotor_frag_replay_root(r,slot,&id,0L)==FD_ROTOR_ACCEPT);
    FD_TEST(!fd_rotor_verify(r));
  }
  notar(r,230UL,230UL);
  parent(r,230UL,230UL,8U,229UL,229UL);
  crank(r,0L);
  fd_rotor_stats_t st; fd_rotor_stats(r,&st);
  FD_TEST(st.other_requests==st.other_request_max);
  fd_rotor_request_t req[1024];
  FD_TEST(!requests(r,0L,req)); /* only old generations in the full heap */
  crank(r,0L);
  ulong n=requests(r,0L,req);
  FD_TEST(n==8UL);
  for( uint idx=0; idx<256; idx+=32 ) FD_TEST(has(req,n,AG_REPAIR_KIND_FEC_ROOT,230UL,idx));
  FD_TEST(!fd_rotor_verify(r));
  free(fd_rotor_delete(r));
}

static void
test_rejected_evidence_and_seed_once( void ) {
  fd_rotor_t * r=new_rotor(512UL);
  fd_rotor_shred_t e={ .kind=FD_ROTOR_SHRED_COMPLETE, .slot=20UL, .idx=0U, .merkle_root=hash(100UL) };
  FD_TEST(fd_rotor_frag_shred(r,&e,0L)==FD_ROTOR_IGNORE);
  fd_rotor_stats_t st; fd_rotor_stats(r,&st); FD_TEST(st.blocks==1UL && !st.fecs);
  notar(r,10UL,10UL); parent(r,10UL,10UL,1U,1UL,1UL);
  fd_rotor_net_t net={ .kind=AG_REPAIR_KIND_PARENT_FEC_COUNT, .slot=10UL, .block_id=hash(10UL),
    .fec_count=2U, .parent_slot=1UL, .parent_id=hash(1UL) };
  FD_TEST(fd_rotor_frag_net(r,&net,0L)==FD_ROTOR_IGNORE);
  net.kind=AG_REPAIR_KIND_FEC_ROOT; net.fec_idx=32U;
  fd_hash_t mr=hash(100UL); memcpy(net.root_prefix,mr.uc,FD_SHRED_MERKLE_NODE_SZ);
  FD_TEST(fd_rotor_frag_net(r,&net,0L)==FD_ROTOR_IGNORE);
  shred(r,20UL,0U,100UL,0,0,0L);
  net.fec_idx=0U; /* same root cannot be attached at another slot */
  FD_TEST(fd_rotor_frag_net(r,&net,0L)==FD_ROTOR_IGNORE);
  fd_rotor_advance(r,0L,64UL,1000UL);
  fd_rotor_request_t req[1024]; requests(r,0L,req);
  ulong n=requests(r,1000L,req);
  for( ulong i=0; i<n; i++ ) FD_TEST(req[i].slot>5UL); /* seed probes are best effort, once */
  FD_TEST(!fd_rotor_verify(r));
  free(fd_rotor_delete(r));
}

static void
test_parent_change_and_configuration( void ) {
  fd_rotor_t * r=new_rotor(512UL);
  fd_rotor_set_block_id_only(r,1,0L);
  shred(r,20UL,0U,120UL,0,0,0L);
  crank(r,0L);
  fd_rotor_request_t req[1024]; FD_TEST(!requests(r,1000L,req));
  fd_rotor_set_block_id_only(r,0,1000L);
  crank(r,1000L);
  ulong n=requests(r,1000L,req);
  FD_TEST(has(req,n,FD_REPAIR_KIND_SHRED,20UL,1U));
  FD_TEST(has(req,n,FD_REPAIR_KIND_HIGHEST_SHRED,20UL,31U));
  fd_rotor_shred_t marker={ .kind=FD_ROTOR_SHRED_DATA, .slot=20UL, .idx=0U,
    .merkle_root=hash(120UL), .has_parent=1, .parent_slot=1UL, .parent_id=hash(1UL) };
  FD_TEST(fd_rotor_frag_shred(r,&marker,1000L)==FD_ROTOR_ACCEPT);
  fd_rotor_block_info_t b;
  FD_TEST(fd_rotor_block_query(r,20UL,&zero,&b) && b.connected);
  marker.idx=32U; marker.merkle_root=hash(121UL); marker.parent_slot=10UL; marker.parent_id=hash(10UL);
  FD_TEST(fd_rotor_frag_shred(r,&marker,1000L)==FD_ROTOR_ACCEPT);
  FD_TEST(fd_rotor_block_query(r,20UL,&zero,&b) && !b.connected);
  crank(r,1000L);
  fd_hash_t other=hash(11UL);
  FD_TEST(fd_rotor_frag_votor(r,10UL,&other,1,1000L)==FD_ROTOR_ACCEPT);
  FD_TEST(fd_rotor_block_query(r,20UL,&zero,&b) && !b.connected && b.cancel);
  n=requests(r,2000L,req);
  for( ulong i=0; i<n; i++ ) FD_TEST(req[i].slot!=20UL);
  FD_TEST(!fd_rotor_verify(r));
  free(fd_rotor_delete(r));
}

int
main( int argc, char ** argv ) {
  fd_boot(&argc,&argv);
  test_sparse_deadlines();
  test_shared_completion_and_final();
  test_pressure_reservation_eviction();
  test_ancestry_and_redelivery();
  test_late_marker_cancel_and_rekey();
  test_seed_and_generation();
  test_final_capacity_and_stale_tokens();
  test_metadata_pressure();
  test_rejected_evidence_and_seed_once();
  test_parent_change_and_configuration();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
