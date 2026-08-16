#include "ag_votor.h"

#define TEST_SHRED_VERSION ((ushort)514)
#include <stdlib.h>

#define SPW AG_SLOTS_PER_WINDOW

#define MAXV 4UL
static ag_aggsig_sk_t      g_sk  [ MAXV ];
static ag_validator_info_t g_info[ MAXV ];

static void
create_signers( ulong n ) {
  FD_TEST( n<=MAXV );
  for( ulong i=0UL; i<n; i++ ) {
    fd_memset( g_sk[i].v, (int)(i*7UL+1UL), AG_AGGSIG_SECKEY_SZ );
    fd_memset( &g_info[i], 0, sizeof(ag_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL;
    ag_aggsig_sk_to_pk( &g_info[i].voting_pubkey, &g_sk[i] );
  }
}

static ag_votor_out_t
fresh_out( void ) {
  ag_votor_out_t out;
  out.msg_cnt     = 0UL;
  out.timeout_cnt = 0UL;
  return out;
}

static void
collect( ag_votor_t const * v,
         ag_votor_out_t *   acc ) {
  ag_votor_out_t const * o = ag_votor_out( v );
  for( ulong i=0UL; i<o->msg_cnt; i++ ) {
    FD_TEST( acc->msg_cnt<AG_VOTOR_OUT_MSG_MAX );
    acc->msgs[ acc->msg_cnt++ ] = o->msgs[ i ];
  }
  for( ulong i=0UL; i<o->timeout_cnt; i++ ) {
    FD_TEST( acc->timeout_cnt<AG_VOTOR_OUT_TIMEOUT_MAX );
    acc->timeouts[ acc->timeout_cnt++ ] = o->timeouts[ i ];
  }
}

static ag_votor_t *
make_votor( fd_wksp_t *      wksp,
            ushort           validator_index,
            ag_votor_out_t * out,
            void **          out_mem ) {
  void * mem = fd_wksp_alloc_laddr( wksp, ag_votor_align(), ag_votor_footprint( 64UL ), 1UL );
  FD_TEST( mem );
  *out_mem = mem;
  /* genesis_block_id() is defined below; the tests use the zero-hash
     genesis convention, so spell it out here. */
  fd_hash_t root_hash; fd_memset( root_hash.uc, 0, sizeof(fd_hash_t) );
  void * sh = ag_votor_new( mem, 64UL, validator_index,
                            ag_aggsig_sign_local, &g_sk[ validator_index ],
                            TEST_SHRED_VERSION, 1234UL,
                            0UL, &root_hash );
  FD_TEST( sh );
  ag_votor_t * v = ag_votor_join( sh );
  FD_TEST( v );
  collect( v, out );
  return v;
}

static fd_hash_t
mk_hash( uchar b ) {
  fd_hash_t h; fd_memset( h.uc, (int)b, sizeof(fd_hash_t) );
  return h;
}

static ag_block_id_t
genesis_block_id( void ) {
  ag_block_id_t id; id.slot = 0UL; fd_memset( id.hash.uc, 0, sizeof(fd_hash_t) );
  return id;
}

static int
count_votes_of_type( ag_votor_out_t const * out,
                     uint                   vt ) {
  int n = 0;
  for( ulong i=0UL; i<out->msg_cnt; i++ ) {
    if( out->msgs[i].kind==AG_CONSENSUS_MESSAGE_VOTE &&
        out->msgs[i].inner.vote.kind==vt ) n++;
  }
  return n;
}

static ag_vote_t const *
first_vote_of_type( ag_votor_out_t const * out,
                    uint                   vt ) {
  for( ulong i=0UL; i<out->msg_cnt; i++ ) {
    if( out->msgs[i].kind==AG_CONSENSUS_MESSAGE_VOTE &&
        out->msgs[i].inner.vote.kind==vt ) return &out->msgs[i].inner.vote;
  }
  return NULL;
}

static void
send_block( ag_votor_t *     v,
            ulong            slot,
            fd_hash_t        hash,
            ag_block_id_t    parent,
            ag_votor_out_t * out ) {
  ag_votor_blockstore_event_t fs = { .kind = AG_VOTOR_BLOCKSTORE_EVENT_FIRST_SHRED };
  fs.inner.first_shred = slot;
  ag_votor_handle_blockstore_event( v, &fs ); collect( v, out );

  ag_votor_blockstore_event_t b = { .kind = AG_VOTOR_BLOCKSTORE_EVENT_BLOCK };
  b.inner.block.slot            = slot;
  b.inner.block.block_id.slot   = slot;
  b.inner.block.block_id.hash   = hash;
  b.inner.block.parent_block_id = parent;
  ag_votor_handle_blockstore_event( v, &b ); collect( v, out );
}

static void
test_timeouts( fd_wksp_t * wksp ) {
  create_signers( 2UL );
  ag_votor_out_t out = fresh_out();
  void * mem; ag_votor_t * v = make_votor( wksp, 0UL, &out, &mem );

  ulong fired_skips[ SPW ];
  ulong skip_cnt = 0UL;
  ulong n_timeouts = out.timeout_cnt;
  ag_votor_timeout_t scheduled[ AG_VOTOR_OUT_TIMEOUT_MAX ];
  for( ulong i=0UL; i<n_timeouts; i++ ) scheduled[i] = out.timeouts[i];

  for( ulong i=0UL; i<n_timeouts; i++ ) {
    ag_votor_out_t o2 = fresh_out();
    ag_votor_handle_timeout_event( v, &scheduled[i] ); collect( v, &o2 );
    for( ulong j=0UL; j<o2.msg_cnt; j++ ) {
      if( o2.msgs[j].kind==AG_CONSENSUS_MESSAGE_VOTE ) {
        FD_TEST( o2.msgs[j].inner.vote.kind==AG_VOTE_TYPE_SKIP );
        ulong s = ag_vote_slot( &o2.msgs[j].inner.vote );

        int seen = 0;
        for( ulong k=0UL; k<skip_cnt; k++ ) if( fired_skips[k]==s ) seen = 1;
        if( !seen ) fired_skips[ skip_cnt++ ] = s;
      }
    }
  }

  FD_TEST( skip_cnt==SPW-1UL );
  for( ulong s=1UL; s<SPW; s++ ) {
    int found = 0;
    for( ulong k=0UL; k<skip_cnt; k++ ) if( fired_skips[k]==s ) found = 1;
    FD_TEST( found );
  }

  for( ulong k=0UL; k<skip_cnt; k++ ) FD_TEST( fired_skips[k]!=0UL );

  ag_votor_delete( ag_votor_leave( v ) );
  fd_wksp_free_laddr( mem );
}

static void
test_notar_and_final( fd_wksp_t * wksp ) {
  create_signers( 2UL );
  ag_votor_out_t out = fresh_out();
  void * mem; ag_votor_t * v = make_votor( wksp, 0UL, &out, &mem );

  ulong slot = 1UL;
  ag_block_id_t parent = genesis_block_id();
  fd_hash_t hash = mk_hash( 0xAB );

  out = fresh_out();
  send_block( v, slot, hash, parent, &out );

  FD_TEST( count_votes_of_type( &out, AG_VOTE_TYPE_NOTAR )==1 );
  ag_vote_t const * nv = first_vote_of_type( &out, AG_VOTE_TYPE_NOTAR );
  FD_TEST( nv && ag_vote_slot( nv )==slot );

  ag_cert_t cert; cert.kind = AG_CERT_TYPE_NOTAR;
  ag_notar_vote_t one; ag_notar_vote_new( &one, slot, &hash, &g_sk[0], 0UL , TEST_SHRED_VERSION );
  FD_TEST( ag_notar_cert_try_new( &cert.inner.notar, &one, 1UL, g_info, 2UL )==AG_CERT_SUCCESS );

  ag_pool_event_t cc = { .kind = AG_POOL_EVENT_CERT_CREATED };
  cc.inner.cert_created = cert;
  out = fresh_out();
  ag_votor_handle_pool_event( v, &cc ); collect( v, &out );

  FD_TEST( count_votes_of_type( &out, AG_VOTE_TYPE_FINAL )==1 );
  ag_vote_t const * fv = first_vote_of_type( &out, AG_VOTE_TYPE_FINAL );
  FD_TEST( fv && ag_vote_slot( fv )==slot );

  int rebroadcast = 0;
  for( ulong i=0UL; i<out.msg_cnt; i++ )
    if( out.msgs[i].kind==AG_CONSENSUS_MESSAGE_CERT ) rebroadcast = 1;
  FD_TEST( rebroadcast );

  ag_votor_delete( ag_votor_leave( v ) );
  fd_wksp_free_laddr( mem );
}

static void
test_notar_out_of_order( fd_wksp_t * wksp ) {
  create_signers( 2UL );
  ag_votor_out_t out = fresh_out();
  void * mem; ag_votor_t * v = make_votor( wksp, 0UL, &out, &mem );

  ulong slot1 = 1UL; fd_hash_t hash1 = mk_hash( 0x11 );
  ulong slot2 = 2UL; fd_hash_t hash2 = mk_hash( 0x22 );

  ag_block_id_t parent2; parent2.slot = slot1; parent2.hash = hash1;
  out = fresh_out();
  send_block( v, slot2, hash2, parent2, &out );
  FD_TEST( count_votes_of_type( &out, AG_VOTE_TYPE_NOTAR )==0 );

  FD_TEST( ag_votor_slot_state( v, slot2 )->has_pending_block );

  ag_block_id_t parent1 = genesis_block_id();
  out = fresh_out();
  send_block( v, slot1, hash1, parent1, &out );
  FD_TEST( count_votes_of_type( &out, AG_VOTE_TYPE_NOTAR )==2 );
  int saw1 = 0, saw2 = 0;
  for( ulong i=0UL; i<out.msg_cnt; i++ ) {
    if( out.msgs[i].kind==AG_CONSENSUS_MESSAGE_VOTE &&
        out.msgs[i].inner.vote.kind==AG_VOTE_TYPE_NOTAR ) {
      ulong s = ag_vote_slot( &out.msgs[i].inner.vote );
      if( s==slot1 ) saw1 = 1;
      if( s==slot2 ) saw2 = 1;
    }
  }
  FD_TEST( saw1 && saw2 );

  ag_votor_delete( ag_votor_leave( v ) );
  fd_wksp_free_laddr( mem );
}

static void
test_safe_to_notar( fd_wksp_t * wksp ) {
  create_signers( 2UL );
  ag_votor_out_t out = fresh_out();
  void * mem; ag_votor_t * v = make_votor( wksp, 0UL, &out, &mem );

  ulong slot = 1UL;

  ulong n_timeouts = out.timeout_cnt;
  ag_votor_timeout_t scheduled[ AG_VOTOR_OUT_TIMEOUT_MAX ];
  for( ulong i=0UL; i<n_timeouts; i++ ) scheduled[i] = out.timeouts[i];
  for( ulong i=0UL; i<n_timeouts; i++ ) {
    ag_votor_out_t o2 = fresh_out();
    ag_votor_handle_timeout_event( v, &scheduled[i] ); collect( v, &o2 );
  }

  fd_hash_t hash = mk_hash( 0x55 );
  ag_pool_event_t e = { .kind = AG_POOL_EVENT_SAFE_TO_NOTAR };
  e.inner.safe_to_notar.slot = slot;
  e.inner.safe_to_notar.hash = hash;
  out = fresh_out();
  ag_votor_handle_pool_event( v, &e ); collect( v, &out );

  FD_TEST( count_votes_of_type( &out, AG_VOTE_TYPE_NOTAR_FALLBACK )==1 );
  ag_vote_t const * nf = first_vote_of_type( &out, AG_VOTE_TYPE_NOTAR_FALLBACK );
  FD_TEST( nf && ag_vote_slot( nf )==slot );
  fd_hash_t const * bh = ag_vote_block_hash( nf );
  FD_TEST( bh && !memcmp( bh->uc, hash.uc, sizeof(fd_hash_t) ) );

  ag_votor_delete( ag_votor_leave( v ) );
  fd_wksp_free_laddr( mem );
}

static void
test_safe_to_skip( fd_wksp_t * wksp ) {
  create_signers( 2UL );
  ag_votor_out_t out = fresh_out();
  void * mem; ag_votor_t * v = make_votor( wksp, 0UL, &out, &mem );

  ulong slot = 1UL;
  ag_block_id_t parent = genesis_block_id();
  fd_hash_t hash = mk_hash( 0x77 );
  out = fresh_out();
  send_block( v, slot, hash, parent, &out );
  FD_TEST( count_votes_of_type( &out, AG_VOTE_TYPE_NOTAR )==1 );

  ag_pool_event_t e = { .kind = AG_POOL_EVENT_SAFE_TO_SKIP };
  e.inner.safe_to_skip = slot;
  out = fresh_out();
  ag_votor_handle_pool_event( v, &e ); collect( v, &out );

  FD_TEST( count_votes_of_type( &out, AG_VOTE_TYPE_SKIP_FALLBACK )==1 );
  ag_vote_t const * sf = first_vote_of_type( &out, AG_VOTE_TYPE_SKIP_FALLBACK );
  FD_TEST( sf && ag_vote_slot( sf )==slot );

  ag_votor_delete( ag_votor_leave( v ) );
  fd_wksp_free_laddr( mem );
}

static void
test_prunes_to_finalized_window( fd_wksp_t * wksp ) {
  create_signers( 2UL );
  ag_votor_out_t out = fresh_out();
  void * mem; ag_votor_t * v = make_votor( wksp, 0UL, &out, &mem );

  ulong finalized    = SPW + 1UL;
  ulong window_start = ag_slot_first_slot_in_window( finalized );
  FD_TEST( window_start > 0UL );
  FD_TEST( window_start < finalized );

  ulong highest = 2UL*SPW;
  for( ulong i=1UL; i<=highest; i++ ) {
    ag_votor_blockstore_event_t fs = { .kind = AG_VOTOR_BLOCKSTORE_EVENT_FIRST_SHRED };
    fs.inner.first_shred = i;
    ag_votor_out_t o2 = fresh_out();
    ag_votor_handle_blockstore_event( v, &fs ); collect( v, &o2 );
  }
  for( ulong i=0UL; i<=highest; i++ ) FD_TEST( ag_votor_slot_state( v, i ) != NULL );

  ag_cert_t cert; cert.kind = AG_CERT_TYPE_FINAL;
  ag_final_vote_t fvote; ag_final_vote_new( &fvote, finalized, &g_sk[1], 1UL , TEST_SHRED_VERSION );
  FD_TEST( ag_final_cert_try_new( &cert.inner.final, &fvote, 1UL, g_info, 2UL )==AG_CERT_SUCCESS );
  ag_pool_event_t cc = { .kind = AG_POOL_EVENT_CERT_CREATED };
  cc.inner.cert_created = cert;
  out = fresh_out();
  ag_votor_handle_pool_event( v, &cc ); collect( v, &out );

  FD_TEST( ag_votor_highest_final_cert_slot( v )==finalized );

  for( ulong s=window_start; s<=ag_slot_last_slot_in_window( window_start ); s++ ) {
    FD_TEST( ag_votor_slot_state( v, s ) != NULL );
  }

  FD_TEST( ag_votor_slot_state( v, 0UL )==NULL );
  FD_TEST( ag_votor_slot_state( v, window_start-1UL )==NULL );

  ag_votor_delete( ag_votor_leave( v ) );
  fd_wksp_free_laddr( mem );
}

static void
test_slashing_invariant( fd_wksp_t * wksp ) {
  create_signers( 2UL );

  {
    ag_votor_out_t out = fresh_out();
    void * mem; ag_votor_t * v = make_votor( wksp, 0UL, &out, &mem );
    ulong slot = 1UL;
    ag_block_id_t parent = genesis_block_id();
    fd_hash_t hash = mk_hash( 0x33 );

    out = fresh_out();
    send_block( v, slot, hash, parent, &out );
    FD_TEST( count_votes_of_type( &out, AG_VOTE_TYPE_NOTAR )==1 );

    ag_pool_event_t sk = { .kind = AG_POOL_EVENT_SAFE_TO_SKIP };
    sk.inner.safe_to_skip = slot;
    out = fresh_out();
    ag_votor_handle_pool_event( v, &sk ); collect( v, &out );
    FD_TEST( ag_votor_slot_state( v, slot )->bad_window );

    ag_cert_t cert; cert.kind = AG_CERT_TYPE_NOTAR;
    ag_notar_vote_t one; ag_notar_vote_new( &one, slot, &hash, &g_sk[0], 0UL , TEST_SHRED_VERSION );
    FD_TEST( ag_notar_cert_try_new( &cert.inner.notar, &one, 1UL, g_info, 2UL )==AG_CERT_SUCCESS );
    ag_pool_event_t cc = { .kind = AG_POOL_EVENT_CERT_CREATED };
    cc.inner.cert_created = cert;
    out = fresh_out();
    ag_votor_handle_pool_event( v, &cc ); collect( v, &out );
    FD_TEST( count_votes_of_type( &out, AG_VOTE_TYPE_FINAL )==0 );

    ag_votor_delete( ag_votor_leave( v ) );
    fd_wksp_free_laddr( mem );
  }

  {
    ag_votor_out_t out = fresh_out();
    void * mem; ag_votor_t * v = make_votor( wksp, 0UL, &out, &mem );
    ulong slot = 1UL;
    fd_hash_t hash = mk_hash( 0x44 );

    ulong n_timeouts = out.timeout_cnt;
    ag_votor_timeout_t scheduled[ AG_VOTOR_OUT_TIMEOUT_MAX ];
    for( ulong i=0UL; i<n_timeouts; i++ ) scheduled[i] = out.timeouts[i];
    for( ulong i=0UL; i<n_timeouts; i++ ) {
      ag_votor_out_t o2 = fresh_out();
      ag_votor_handle_timeout_event( v, &scheduled[i] ); collect( v, &o2 );
    }
    FD_TEST( ag_votor_slot_state( v, slot )->bad_window );
    FD_TEST( ag_votor_slot_state( v, slot )->voted );

    ag_cert_t cert; cert.kind = AG_CERT_TYPE_NOTAR;
    ag_notar_vote_t one; ag_notar_vote_new( &one, slot, &hash, &g_sk[0], 0UL , TEST_SHRED_VERSION );
    FD_TEST( ag_notar_cert_try_new( &cert.inner.notar, &one, 1UL, g_info, 2UL )==AG_CERT_SUCCESS );
    ag_pool_event_t cc = { .kind = AG_POOL_EVENT_CERT_CREATED };
    cc.inner.cert_created = cert;
    out = fresh_out();
    ag_votor_handle_pool_event( v, &cc ); collect( v, &out );
    FD_TEST( count_votes_of_type( &out, AG_VOTE_TYPE_FINAL )==0 );

    ag_votor_delete( ag_votor_leave( v ) );
    fd_wksp_free_laddr( mem );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_cnt = 16384UL;
  char *      page_sz  = "normal";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_timeouts( wksp );
  test_notar_and_final( wksp );
  test_notar_out_of_order( wksp );
  test_safe_to_notar( wksp );
  test_safe_to_skip( wksp );
  test_prunes_to_finalized_window( wksp );
  test_slashing_invariant( wksp );

  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
