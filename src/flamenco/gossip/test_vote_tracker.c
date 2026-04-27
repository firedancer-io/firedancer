#include "fd_gossip.h"
#include "../../util/fd_util.h"
#include "../../disco/topo/fd_topob.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../../tango/dcache/fd_dcache.h"

/* Mock callbacks --------------------------------------------------- */

static void
mock_send_fn( void *                ctx FD_PARAM_UNUSED,
              fd_stem_context_t *   stem FD_PARAM_UNUSED,
              uchar const *         data FD_PARAM_UNUSED,
              ulong                 sz FD_PARAM_UNUSED,
              fd_ip4_port_t const * peer_address FD_PARAM_UNUSED,
              ulong                 now FD_PARAM_UNUSED ) {
}

static ulong mock_signature = 0UL;

static void
mock_sign_fn( void *        ctx FD_PARAM_UNUSED,
              uchar const * data FD_PARAM_UNUSED,
              ulong         sz FD_PARAM_UNUSED,
              int           sign_type FD_PARAM_UNUSED,
              uchar *       out_signature ) {
  /* Each signature must be unique so that the CRDS fast-duplicate
     check (first 8 bytes of the serialized value) does not falsely
     trigger when a vote index is reused after eviction. */
  fd_memset( out_signature, 0, 64UL );
  FD_STORE( ulong, out_signature, mock_signature );
  mock_signature++;
}

static void
mock_ping_tracker_change_fn( void *        ctx FD_PARAM_UNUSED,
                             uchar const * peer_pubkey FD_PARAM_UNUSED,
                             fd_ip4_port_t peer_address FD_PARAM_UNUSED,
                             long          now FD_PARAM_UNUSED,
                             int           change_type FD_PARAM_UNUSED ) {
}

static void
mock_activity_update_fn( void *                           ctx FD_PARAM_UNUSED,
                         fd_pubkey_t const *              identity FD_PARAM_UNUSED,
                         fd_gossip_contact_info_t const * ci FD_PARAM_UNUSED,
                         int                              change_type FD_PARAM_UNUSED ) {
}

/* Test infrastructure ---------------------------------------------- */

#define LINK_DEPTH      (128UL)
#define LINK_MTU        (4096UL)
#define TEST_MAX_VALUES (256UL)

static fd_topo_t _topo[ 1 ];

static fd_topo_link_t *
create_link( fd_topo_t *  topo,
             fd_wksp_t *  wksp,
             char const * name,
             ulong        depth,
             ulong        mtu ) {
  fd_topo_link_t * link = fd_topob_link( topo, name, wksp->name, depth, mtu, 1UL );

  fd_topo_obj_t *  mcache_obj = &topo->objs[ link->mcache_obj_id ];
  void *           mcache_mem = fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( depth, mtu ), 1UL );
  fd_frag_meta_t * mcache     = fd_mcache_join( fd_mcache_new( mcache_mem, depth, mtu, 0UL ) );
  FD_TEST( mcache );
  link->mcache       = mcache;
  mcache_obj->offset = fd_wksp_gaddr_fast( wksp, mcache_mem );

  if( mtu ) {
    fd_topo_obj_t * dcache_obj     = &topo->objs[ link->dcache_obj_id ];
    ulong           dcache_data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );
    void *          dcache_mem     = fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( dcache_data_sz, 0UL ), 1UL );
    uchar *         dcache         = fd_dcache_join( fd_dcache_new( dcache_mem, dcache_data_sz, 0UL ) );
    FD_TEST( dcache );
    link->dcache       = dcache;
    dcache_obj->offset = fd_wksp_gaddr_fast( wksp, dcache_mem );
  }

  return link;
}

struct test_ctx {
  fd_wksp_t *          wksp;
  fd_gossip_t *        gossip;
  fd_gossip_out_ctx_t  gossip_update_out[ 1 ];
  fd_gossip_out_ctx_t  gossip_net_out[ 1 ];
  fd_stem_context_t    stem[ 1 ];

  fd_frag_meta_t *     mcaches_arr[ 2 ];
  ulong                seqs[ 2 ];
  ulong                depths[ 2 ];
  ulong                cr_avail[ 2 ];
  ulong                min_cr_avail_val;
  int                  out_reliable[ 2 ];

  fd_rng_t             _rng[ 1 ];
};

typedef struct test_ctx test_ctx_t;

#define SECONDS_TO_NANOS(s) ((s) * 1000L * 1000L * 1000L)

static void
test_ctx_init( test_ctx_t * tc,
               uchar        identity_byte,
               long         now ) {
  fd_memset( tc, 0, sizeof(test_ctx_t) );

  fd_rng_t * rng = fd_rng_join( fd_rng_new( tc->_rng, 0U, 0UL ) );
  FD_TEST( rng );

  ulong page_cnt = 65536UL;
  ulong cpu_idx = 0UL;
  tc->wksp = fd_wksp_new_anon( "wksp", FD_SHMEM_NORMAL_PAGE_SZ, 1UL, &page_cnt, &cpu_idx, 0U, 0UL );
  FD_TEST( tc->wksp );

  fd_topo_t *      topo      = fd_topob_new( _topo, "test_vt" );
  fd_topo_wksp_t * topo_wksp = fd_topob_wksp( topo, "wksp" );
  topo_wksp->wksp = tc->wksp;

  fd_topo_link_t * link_update = create_link( topo, tc->wksp, "gossip_upd", LINK_DEPTH, LINK_MTU );
  fd_topo_link_t * link_net    = create_link( topo, tc->wksp, "gossip_net", LINK_DEPTH, LINK_MTU );

  tc->gossip_update_out->mem    = tc->wksp;
  tc->gossip_update_out->chunk0 = fd_dcache_compact_chunk0( tc->wksp, link_update->dcache );
  tc->gossip_update_out->wmark  = fd_dcache_compact_wmark( tc->wksp, link_update->dcache, LINK_MTU );
  tc->gossip_update_out->chunk  = tc->gossip_update_out->chunk0;
  tc->gossip_update_out->idx    = 0UL;

  tc->gossip_net_out->mem    = tc->wksp;
  tc->gossip_net_out->chunk0 = fd_dcache_compact_chunk0( tc->wksp, link_net->dcache );
  tc->gossip_net_out->wmark  = fd_dcache_compact_wmark( tc->wksp, link_net->dcache, LINK_MTU );
  tc->gossip_net_out->chunk  = tc->gossip_net_out->chunk0;
  tc->gossip_net_out->idx    = 1UL;

  tc->mcaches_arr[ 0 ]   = link_update->mcache;
  tc->mcaches_arr[ 1 ]   = link_net->mcache;
  tc->seqs[ 0 ]          = 0UL;
  tc->seqs[ 1 ]          = 0UL;
  tc->depths[ 0 ]        = LINK_DEPTH;
  tc->depths[ 1 ]        = LINK_DEPTH;
  tc->cr_avail[ 0 ]      = LINK_DEPTH;
  tc->cr_avail[ 1 ]      = LINK_DEPTH;
  tc->min_cr_avail_val   = LINK_DEPTH;
  tc->out_reliable[ 0 ]  = 0;
  tc->out_reliable[ 1 ]  = 0;

  tc->stem->mcaches             = tc->mcaches_arr;
  tc->stem->seqs                = tc->seqs;
  tc->stem->depths              = tc->depths;
  tc->stem->cr_avail            = tc->cr_avail;
  tc->stem->min_cr_avail        = &tc->min_cr_avail_val;
  tc->stem->cr_decrement_amount = 1UL;
  tc->stem->out_reliable        = tc->out_reliable;

  fd_pubkey_t identity = { .ul = { identity_byte } };

  fd_gossip_contact_info_t ci[1];
  fd_memset( ci, 0, sizeof(fd_gossip_contact_info_t) );

  fd_ip4_port_t entrypoint;
  entrypoint.addr = 0x01020304U;
  entrypoint.port = 8001;

  ulong gossip_fp = fd_gossip_footprint( TEST_MAX_VALUES, 1UL );
  FD_TEST( gossip_fp );

  void * gossip_mem = fd_wksp_alloc_laddr( tc->wksp, fd_gossip_align(), gossip_fp, 1UL );
  FD_TEST( gossip_mem );

  void * gossip_shmem = fd_gossip_new( gossip_mem,
                                       rng,
                                       TEST_MAX_VALUES,
                                       1UL,
                                       &entrypoint,
                                       identity.uc,
                                       ci,
                                       now,
                                       mock_send_fn,  NULL,
                                       mock_sign_fn,  NULL,
                                       mock_ping_tracker_change_fn,
                                       NULL,
                                       mock_activity_update_fn,
                                       NULL,
                                       tc->gossip_update_out,
                                       tc->gossip_net_out );
  FD_TEST( gossip_shmem );

  tc->gossip = fd_gossip_join( gossip_shmem );
  FD_TEST( tc->gossip );
}

static void
test_ctx_fini( test_ctx_t * tc ) {
  fd_wksp_delete_anon( tc->wksp );
  tc->wksp   = NULL;
  tc->gossip = NULL;
}

/* ------------------------------------------------------------------ *
   Test cases
 * ------------------------------------------------------------------ */

static void
test_fill_votes( void ) {
  FD_LOG_NOTICE(( "Running test_fill_votes" ));

  test_ctx_t tc[ 1 ];
  long now = SECONDS_TO_NANOS( 100L );
  test_ctx_init( tc, 1, now );

  uchar txn[ 64 ];
  fd_memset( txn, 0xAB, sizeof(txn) );

  for( ulong i=0UL; i<FD_GOSSIP_VOTE_IDX_MAX; i++ ) {
    long t  = now + (long)(i+1UL) * SECONDS_TO_NANOS( 1L );
    int  rc = fd_gossip_push_vote( tc->gossip, i+1UL, txn, sizeof(txn), tc->stem, t );
    FD_TEST( rc==0 );
  }

  test_ctx_fini( tc );
  FD_LOG_NOTICE(( "test_fill_votes passed" ));
}

static void
test_eviction( void ) {
  FD_LOG_NOTICE(( "Running test_eviction" ));

  test_ctx_t tc[ 1 ];
  long now = SECONDS_TO_NANOS( 200L );
  test_ctx_init( tc, 2, now );

  uchar txn[ 64 ];
  fd_memset( txn, 0xCD, sizeof(txn) );

  for( ulong i=0UL; i<FD_GOSSIP_VOTE_IDX_MAX; i++ ) {
    long t  = now + (long)(i+1UL) * SECONDS_TO_NANOS( 1L );
    int  rc = fd_gossip_push_vote( tc->gossip, i+1UL, txn, sizeof(txn), tc->stem, t );
    FD_TEST( rc==0 );
  }

  long t_evict = now + (long)(FD_GOSSIP_VOTE_IDX_MAX+1UL) * SECONDS_TO_NANOS( 1L );
  int  rc      = fd_gossip_push_vote( tc->gossip, FD_GOSSIP_VOTE_IDX_MAX+1UL, txn, sizeof(txn), tc->stem, t_evict );
  FD_TEST( rc==0 );

  /* Push several more votes to exercise repeated evictions */
  for( ulong i=1UL; i<=6UL; i++ ) {
    long t_more = t_evict + (long)i * SECONDS_TO_NANOS( 1L );
    int  rc2    = fd_gossip_push_vote( tc->gossip, FD_GOSSIP_VOTE_IDX_MAX+1UL+i, txn, sizeof(txn), tc->stem, t_more );
    FD_TEST( rc2==0 );
  }

  test_ctx_fini( tc );
  FD_LOG_NOTICE(( "test_eviction passed" ));
}

static void
test_identity_change_clears_votes( void ) {
  FD_LOG_NOTICE(( "Running test_identity_change_clears_votes" ));

  test_ctx_t tc[ 1 ];
  long now = SECONDS_TO_NANOS( 300L );
  test_ctx_init( tc, 3, now );

  uchar txn[ 64 ];
  fd_memset( txn, 0x11, sizeof(txn) );

  /* Push 6 votes under original identity */
  for( ulong i=0UL; i<6UL; i++ ) {
    long t  = now + (long)(i+1UL) * SECONDS_TO_NANOS( 1L );
    int  rc = fd_gossip_push_vote( tc->gossip, i+1UL, txn, sizeof(txn), tc->stem, t );
    FD_TEST( rc==0 );
  }

  /* Switch identity — this clears the my_votes tracker */
  long id_time = now + 7L * SECONDS_TO_NANOS( 1L );
  fd_gossip_set_identity( tc->gossip, ((fd_pubkey_t){ .ul = { 44UL }}).uc, id_time );

  /* With the vote tracker cleared, we should be able to push
     FD_GOSSIP_VOTE_IDX_MAX fresh votes under the new identity. */
  for( ulong i=0UL; i<FD_GOSSIP_VOTE_IDX_MAX; i++ ) {
    long t  = id_time + (long)(i+1UL) * SECONDS_TO_NANOS( 1L );
    int  rc = fd_gossip_push_vote( tc->gossip, i+1UL, txn, sizeof(txn), tc->stem, t );
    FD_TEST( rc==0 );
  }

  test_ctx_fini( tc );
  FD_LOG_NOTICE(( "test_identity_change_clears_votes passed" ));
}

static void
test_repeated_identity_changes( void ) {
  FD_LOG_NOTICE(( "Running test_repeated_identity_changes" ));

  test_ctx_t tc[ 1 ];
  long now = SECONDS_TO_NANOS( 500L );
  test_ctx_init( tc, 5, now );

  uchar txn[ 64 ];
  fd_memset( txn, 0x33, sizeof(txn) );
  long t = now;

  for( ulong round=0UL; round<5UL; round++ ) {
    if( round>0UL ) {
      t += SECONDS_TO_NANOS( 1L );
      fd_gossip_set_identity( tc->gossip, ((fd_pubkey_t){ .ul = { 60U + (uint)round }}).uc, t );
    }

    for( ulong i=0UL; i<FD_GOSSIP_VOTE_IDX_MAX; i++ ) {
      t += SECONDS_TO_NANOS( 1L );
      int rc = fd_gossip_push_vote( tc->gossip, i+1UL, txn, sizeof(txn), tc->stem, t );
      FD_TEST( rc==0 );
    }
  }

  test_ctx_fini( tc );
  FD_LOG_NOTICE(( "test_repeated_identity_changes passed" ));
}

static void
test_many_votes( void ) {
  FD_LOG_NOTICE(( "Running test_many_votes" ));

  test_ctx_t tc[ 1 ];
  long now = SECONDS_TO_NANOS( 600L );
  test_ctx_init( tc, 6, now );

  uchar txn[ 64 ];
  fd_memset( txn, 0x44, sizeof(txn) );

  for( ulong i=0UL; i<100UL; i++ ) {
    long t  = now + (long)(i+1UL) * SECONDS_TO_NANOS( 1L );
    int  rc = fd_gossip_push_vote( tc->gossip, i+1UL, txn, sizeof(txn), tc->stem, t );
    FD_TEST( rc==0 );
  }

  test_ctx_fini( tc );
  FD_LOG_NOTICE(( "test_many_votes passed" ));
}

static void
test_eviction_tiebreak( void ) {
  FD_LOG_NOTICE(( "Running test_eviction_tiebreak" ));

  test_ctx_t tc[ 1 ];
  long now = SECONDS_TO_NANOS( 700L );
  test_ctx_init( tc, 7, now );

  uchar txn[ 64 ];
  fd_memset( txn, 0x77, sizeof(txn) );

  long same_now = now + SECONDS_TO_NANOS( 5L );
  for( ulong i=0UL; i<FD_GOSSIP_VOTE_IDX_MAX; i++ ) {
    int rc = fd_gossip_push_vote( tc->gossip, i+1UL, txn, sizeof(txn), tc->stem, same_now );
    FD_TEST( rc==0 );
  }

  long newer_now = same_now + SECONDS_TO_NANOS( 1L );
  int  rc = fd_gossip_push_vote( tc->gossip, FD_GOSSIP_VOTE_IDX_MAX+1UL, txn, sizeof(txn), tc->stem, newer_now );
  FD_TEST( rc==0 );

  /* Continue pushing to verify tiebreak works repeatedly */
  for( ulong i=2UL; i<=FD_GOSSIP_VOTE_IDX_MAX; i++ ) {
    long t  = newer_now + (long)i * SECONDS_TO_NANOS( 1L );
    int  rc2 = fd_gossip_push_vote( tc->gossip, FD_GOSSIP_VOTE_IDX_MAX+i, txn, sizeof(txn), tc->stem, t );
    FD_TEST( rc2==0 );
  }

  test_ctx_fini( tc );
  FD_LOG_NOTICE(( "test_eviction_tiebreak passed" ));
}

static void
test_full_lifecycle( void ) {
  FD_LOG_NOTICE(( "Running test_full_lifecycle" ));

  test_ctx_t tc[ 1 ];
  long now = SECONDS_TO_NANOS( 800L );
  test_ctx_init( tc, 8, now );

  uchar txn[ 64 ];
  fd_memset( txn, 0x88, sizeof(txn) );
  long t = now;

  /* Fill tracker under identity A */
  for( ulong i=0UL; i<FD_GOSSIP_VOTE_IDX_MAX; i++ ) {
    t += SECONDS_TO_NANOS( 1L );
    int rc = fd_gossip_push_vote( tc->gossip, i+1UL, txn, sizeof(txn), tc->stem, t );
    FD_TEST( rc==0 );
  }

  /* Switch to identity B, fill again */
  t += SECONDS_TO_NANOS( 1L );
  fd_gossip_set_identity( tc->gossip, ((fd_pubkey_t){ .ul = { 0xBB }}).uc, t );

  for( ulong i=0UL; i<FD_GOSSIP_VOTE_IDX_MAX; i++ ) {
    t += SECONDS_TO_NANOS( 1L );
    int rc = fd_gossip_push_vote( tc->gossip, i+1UL, txn, sizeof(txn), tc->stem, t );
    FD_TEST( rc==0 );
  }

  /* Push 6 more votes under identity B (evictions) */
  for( ulong i=FD_GOSSIP_VOTE_IDX_MAX; i<FD_GOSSIP_VOTE_IDX_MAX+6UL; i++ ) {
    t += SECONDS_TO_NANOS( 1L );
    int rc = fd_gossip_push_vote( tc->gossip, i+1UL, txn, sizeof(txn), tc->stem, t );
    FD_TEST( rc==0 );
  }

  /* Switch to identity C, push a final round */
  t += SECONDS_TO_NANOS( 1L );
  fd_gossip_set_identity( tc->gossip, ((fd_pubkey_t){ .ul = { 0xCC }}).uc, t );

  for( ulong i=0UL; i<FD_GOSSIP_VOTE_IDX_MAX; i++ ) {
    t += SECONDS_TO_NANOS( 1L );
    int rc = fd_gossip_push_vote( tc->gossip, i+1UL, txn, sizeof(txn), tc->stem, t );
    FD_TEST( rc==0 );
  }

  test_ctx_fini( tc );
  FD_LOG_NOTICE(( "test_full_lifecycle passed" ));
}

static void
test_vote_refresh( void ) {
  FD_LOG_NOTICE(( "Running test_vote_refresh" ));

  test_ctx_t tc[ 1 ];
  long now = SECONDS_TO_NANOS( 900L );
  test_ctx_init( tc, 9, now );

  uchar txn[ 64 ];
  fd_memset( txn, 0x99, sizeof(txn) );

  /* Push a few votes at distinct slots */
  for( ulong i=0UL; i<6UL; i++ ) {
    long t  = now + (long)(i+1UL) * SECONDS_TO_NANOS( 1L );
    int  rc = fd_gossip_push_vote( tc->gossip, i+1UL, txn, sizeof(txn), tc->stem, t );
    FD_TEST( rc==0 );
  }

  /* Refresh the last vote (slot 6) several times with increasing
     wallclock, mimicking Agave's refresh_vote behavior when a
     vote transaction's blockhash is getting stale. */
  for( ulong r=0UL; r<10UL; r++ ) {
    long t  = now + (long)(7UL+r) * SECONDS_TO_NANOS( 1L );
    int  rc = fd_gossip_push_vote( tc->gossip, 6UL, txn, sizeof(txn), tc->stem, t );
    FD_TEST( rc==0 );
  }

  /* After the refreshes we should still be able to push a new,
     higher vote without issues. */
  long t_new = now + 20L * SECONDS_TO_NANOS( 1L );
  int  rc    = fd_gossip_push_vote( tc->gossip, 7UL, txn, sizeof(txn), tc->stem, t_new );
  FD_TEST( rc==0 );

  /* Fill the remaining slots and then refresh the highest vote
     while all slots are occupied. */
  for( ulong i=8UL; i<7UL+FD_GOSSIP_VOTE_IDX_MAX; i++ ) {
    t_new += SECONDS_TO_NANOS( 1L );
    int rc2 = fd_gossip_push_vote( tc->gossip, i, txn, sizeof(txn), tc->stem, t_new );
    FD_TEST( rc2==0 );
  }

  ulong highest_slot = 6UL + FD_GOSSIP_VOTE_IDX_MAX;
  for( ulong r=0UL; r<5UL; r++ ) {
    t_new += SECONDS_TO_NANOS( 1L );
    int rc2 = fd_gossip_push_vote( tc->gossip, highest_slot, txn, sizeof(txn), tc->stem, t_new );
    FD_TEST( rc2==0 );
  }

  test_ctx_fini( tc );
  FD_LOG_NOTICE(( "test_vote_refresh passed" ));
}

/* ------------------------------------------------------------------ */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_fill_votes();
  test_eviction();
  test_identity_change_clears_votes();
  test_repeated_identity_changes();
  test_many_votes();
  test_eviction_tiebreak();
  test_full_lifecycle();
  test_vote_refresh();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
