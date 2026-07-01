#include "fd_votor.h"
#include <stdlib.h>

/* Ports alpenglow/src/consensus/votor.rs mod tests.  The async event loop and
   all2all.broadcast are collapsed: we drive the handlers directly and assert
   on the emitted action/timeout streams.  The Rust tests build a 2-validator
   set; here we only need the validator set's count to size aggregate-signature
   bitmasks where certs are constructed, plus secret keys to sign votes.

   Ported cases:
     - timeouts                  : firing the genesis-window timeouts makes us
                                   skip every slot in the window (but never the
                                   genesis slot, which is retired).
     - notar_and_final           : seeing a block -> notar; a notar cert ->
                                   final.
     - notar_out_of_order        : a later block waits as pending until the
                                   earlier block arrives, then both notar.
     - safe_to_notar             : SafeToNotar -> notar-fallback vote.
     - safe_to_skip              : SafeToSkip  -> skip-fallback vote.
     - prunes_to_finalized_window: finalizing a mid-window slot drops only the
                                   slots strictly before its window.
     - slashing_invariant        : after any skip / notar-fallback /
                                   skip-fallback for a slot, Final is never
                                   emitted for it (the bad_window invariant). */

#define SPW FD_ALPENGLOW_SLOTS_PER_WINDOW

#define MAXV 4UL
static fd_aggsig_sk_t      g_sk  [ MAXV ];
static fd_validator_info_t g_info[ MAXV ];

static void
create_signers( ulong n ) {
  FD_TEST( n<=MAXV );
  for( ulong i=0UL; i<n; i++ ) {
    fd_memset( g_sk[i].v, (int)(i*7UL+1UL), FD_AGGSIG_SECKEY_SZ );
    fd_memset( &g_info[i], 0, sizeof(fd_validator_info_t) );
    g_info[i].id    = i;
    g_info[i].stake = 1UL;
    fd_aggsig_sk_to_pk( &g_info[i].voting_pubkey, &g_sk[i] );
  }
}

/* Out-buffer scaffolding.  Generously sized: a single handler emits at most a
   handful of votes/certs plus, via set_timeouts, one crashed-leader timeout +
   SPW per-slot timeouts. */

#define OUT_MSG_MAX     64UL
#define OUT_TIMEOUT_MAX 64UL

static fd_consensus_message_t g_msgs    [ OUT_MSG_MAX     ];
static fd_votor_timeout_t     g_timeouts[ OUT_TIMEOUT_MAX ];

static fd_votor_out_t
fresh_out( void ) {
  fd_votor_out_t out = {
    .msgs        = g_msgs,
    .msg_cnt     = 0UL,
    .msg_max     = OUT_MSG_MAX,
    .timeouts    = g_timeouts,
    .timeout_cnt = 0UL,
    .timeout_max = OUT_TIMEOUT_MAX
  };
  return out;
}

static fd_votor_t *
make_votor( fd_wksp_t * wksp, ushort validator_index, fd_votor_out_t * out, void ** out_mem ) {
  void * mem = fd_wksp_alloc_laddr( wksp, fd_votor_align(), fd_votor_footprint( 64UL ), 1UL );
  FD_TEST( mem );
  *out_mem = mem;
  void * sh = fd_votor_new( mem, 64UL, &g_sk[ validator_index ], 1234UL, out );
  FD_TEST( sh );
  return fd_votor_join( sh );
}

static fd_hash_t
mk_hash( uchar b ) {
  fd_hash_t h; fd_memset( h.uc, (int)b, sizeof(fd_hash_t) );
  return h;
}

static fd_block_id_t
genesis_block_id( void ) {
  fd_block_id_t id; id.slot = 0UL; fd_memset( id.hash.uc, 0, sizeof(fd_hash_t) );
  return id;
}

/* Helpers to scan the emitted message stream. */

static int
count_votes_of_type( fd_votor_out_t const * out, uint vt ) {
  int n = 0;
  for( ulong i=0UL; i<out->msg_cnt; i++ ) {
    if( out->msgs[i].discriminant==FD_CONSENSUS_MESSAGE_VOTE &&
        out->msgs[i].inner.vote.discriminant==vt ) n++;
  }
  return n;
}

static fd_ag_vote_t const *
first_vote_of_type( fd_votor_out_t const * out, uint vt ) {
  for( ulong i=0UL; i<out->msg_cnt; i++ ) {
    if( out->msgs[i].discriminant==FD_CONSENSUS_MESSAGE_VOTE &&
        out->msgs[i].inner.vote.discriminant==vt ) return &out->msgs[i].inner.vote;
  }
  return NULL;
}

/* send_block: FirstShred(slot) then Block{slot, (slot,hash), parent}. */

static void
send_block( fd_votor_t * v, ulong slot, fd_hash_t hash, fd_block_id_t parent, fd_votor_out_t * out ) {
  fd_votor_blockstore_event_t fs = { .discriminant = FD_VOTOR_BLOCKSTORE_EVENT_FIRST_SHRED };
  fs.inner.first_shred = slot;
  fd_votor_handle_blockstore_event( v, &fs, out );

  fd_votor_blockstore_event_t b = { .discriminant = FD_VOTOR_BLOCKSTORE_EVENT_BLOCK };
  b.inner.block.slot            = slot;
  b.inner.block.block_id.slot   = slot;
  b.inner.block.block_id.hash   = hash;
  b.inner.block.parent_block_id = parent;
  fd_votor_handle_blockstore_event( v, &b, out );
}

/* ---------------------------------------------------------------------- */

/* timeouts: genesis-window timeouts make us skip every slot in the window
   except the (retired) genesis slot. */

static void
test_timeouts( fd_wksp_t * wksp ) {
  create_signers( 2UL );
  fd_votor_out_t out = fresh_out();
  void * mem; fd_votor_t * v = make_votor( wksp, 0UL, &out, &mem );

  /* fd_votor_new emitted the genesis window's timeouts.  Fire each. */
  ulong fired_skips[ SPW ];
  ulong skip_cnt = 0UL;
  ulong n_timeouts = out.timeout_cnt;
  fd_votor_timeout_t scheduled[ OUT_TIMEOUT_MAX ];
  for( ulong i=0UL; i<n_timeouts; i++ ) scheduled[i] = out.timeouts[i];

  for( ulong i=0UL; i<n_timeouts; i++ ) {
    fd_votor_out_t o2 = fresh_out();
    fd_votor_handle_timeout_event( v, &scheduled[i], &o2 );
    for( ulong j=0UL; j<o2.msg_cnt; j++ ) {
      if( o2.msgs[j].discriminant==FD_CONSENSUS_MESSAGE_VOTE ) {
        FD_TEST( o2.msgs[j].inner.vote.discriminant==FD_VOTE_TYPE_SKIP );
        ulong s = fd_vote_slot( &o2.msgs[j].inner.vote );
        /* dedup: try_skip_window only votes once per slot */
        int seen = 0;
        for( ulong k=0UL; k<skip_cnt; k++ ) if( fired_skips[k]==s ) seen = 1;
        if( !seen ) fired_skips[ skip_cnt++ ] = s;
      }
    }
  }

  /* should have voted skip for slots 1..SPW-1 (genesis slot 0 is retired) */
  FD_TEST( skip_cnt==SPW-1UL );
  for( ulong s=1UL; s<SPW; s++ ) {
    int found = 0;
    for( ulong k=0UL; k<skip_cnt; k++ ) if( fired_skips[k]==s ) found = 1;
    FD_TEST( found );
  }
  /* genesis slot must never be skipped */
  for( ulong k=0UL; k<skip_cnt; k++ ) FD_TEST( fired_skips[k]!=0UL );

  fd_votor_delete( fd_votor_leave( v ) );
  fd_wksp_free_laddr( mem );
}

/* notar_and_final: seeing a block -> notar; notar cert -> final. */

static void
test_notar_and_final( fd_wksp_t * wksp ) {
  create_signers( 2UL );
  fd_votor_out_t out = fresh_out();
  void * mem; fd_votor_t * v = make_votor( wksp, 0UL, &out, &mem );

  ulong slot = 1UL; /* Slot::genesis().next() */
  fd_block_id_t parent = genesis_block_id();
  fd_hash_t hash = mk_hash( 0xAB );

  out = fresh_out();
  send_block( v, slot, hash, parent, &out );

  /* expect exactly one notar vote for slot */
  FD_TEST( count_votes_of_type( &out, FD_VOTE_TYPE_NOTAR )==1 );
  fd_ag_vote_t const * nv = first_vote_of_type( &out, FD_VOTE_TYPE_NOTAR );
  FD_TEST( nv && fd_vote_slot( nv )==slot );

  /* build a notar cert from that vote and feed CertCreated -> expect final */
  fd_cert_t cert; cert.discriminant = FD_CERT_TYPE_NOTAR;
  fd_notar_vote_t one; fd_notar_vote_new( &one, slot, &hash, &g_sk[0], 0UL );
  FD_TEST( fd_notar_cert_try_new( &cert.inner.notar, &one, 1UL, g_info, 2UL )==FD_CERT_SUCCESS );

  fd_votor_pool_event_t cc = { .discriminant = FD_VOTOR_POOL_EVENT_CERT_CREATED };
  cc.inner.cert_created = cert;
  out = fresh_out();
  fd_votor_handle_pool_event( v, &cc, &out );

  FD_TEST( count_votes_of_type( &out, FD_VOTE_TYPE_FINAL )==1 );
  fd_ag_vote_t const * fv = first_vote_of_type( &out, FD_VOTE_TYPE_FINAL );
  FD_TEST( fv && fd_vote_slot( fv )==slot );
  /* the cert itself is re-broadcast */
  int rebroadcast = 0;
  for( ulong i=0UL; i<out.msg_cnt; i++ )
    if( out.msgs[i].discriminant==FD_CONSENSUS_MESSAGE_CERT ) rebroadcast = 1;
  FD_TEST( rebroadcast );

  fd_votor_delete( fd_votor_leave( v ) );
  fd_wksp_free_laddr( mem );
}

/* notar_out_of_order: a later block waits pending until the earlier block
   arrives, then both notar. */

static void
test_notar_out_of_order( fd_wksp_t * wksp ) {
  create_signers( 2UL );
  fd_votor_out_t out = fresh_out();
  void * mem; fd_votor_t * v = make_votor( wksp, 0UL, &out, &mem );

  ulong slot1 = 1UL; fd_hash_t hash1 = mk_hash( 0x11 );
  ulong slot2 = 2UL; fd_hash_t hash2 = mk_hash( 0x22 );

  /* give later block (slot2) first; its parent is (slot1,hash1), which we have
     not voted notar for yet -> should NOT vote */
  fd_block_id_t parent2; parent2.slot = slot1; parent2.hash = hash1;
  out = fresh_out();
  send_block( v, slot2, hash2, parent2, &out );
  FD_TEST( count_votes_of_type( &out, FD_VOTE_TYPE_NOTAR )==0 );
  /* slot2 should be pending */
  FD_TEST( fd_votor_slot_state( v, slot2 )->has_pending_block );

  /* now the earlier block (slot1) with genesis parent -> notar slot1, then
     check_pending_blocks lets slot2 notar too */
  fd_block_id_t parent1 = genesis_block_id();
  out = fresh_out();
  send_block( v, slot1, hash1, parent1, &out );
  FD_TEST( count_votes_of_type( &out, FD_VOTE_TYPE_NOTAR )==2 );
  int saw1 = 0, saw2 = 0;
  for( ulong i=0UL; i<out.msg_cnt; i++ ) {
    if( out.msgs[i].discriminant==FD_CONSENSUS_MESSAGE_VOTE &&
        out.msgs[i].inner.vote.discriminant==FD_VOTE_TYPE_NOTAR ) {
      ulong s = fd_vote_slot( &out.msgs[i].inner.vote );
      if( s==slot1 ) saw1 = 1;
      if( s==slot2 ) saw2 = 1;
    }
  }
  FD_TEST( saw1 && saw2 );

  fd_votor_delete( fd_votor_leave( v ) );
  fd_wksp_free_laddr( mem );
}

/* safe_to_notar: SafeToNotar -> notar-fallback vote (after the window has
   been skipped). */

static void
test_safe_to_notar( fd_wksp_t * wksp ) {
  create_signers( 2UL );
  fd_votor_out_t out = fresh_out();
  void * mem; fd_votor_t * v = make_votor( wksp, 0UL, &out, &mem );

  ulong slot = 1UL;
  /* fire all genesis-window timeouts so slots 1..SPW-1 are skipped */
  ulong n_timeouts = out.timeout_cnt;
  fd_votor_timeout_t scheduled[ OUT_TIMEOUT_MAX ];
  for( ulong i=0UL; i<n_timeouts; i++ ) scheduled[i] = out.timeouts[i];
  for( ulong i=0UL; i<n_timeouts; i++ ) {
    fd_votor_out_t o2 = fresh_out();
    fd_votor_handle_timeout_event( v, &scheduled[i], &o2 );
  }

  /* SafeToNotar((slot, hash)) -> notar-fallback */
  fd_hash_t hash = mk_hash( 0x55 );
  fd_votor_pool_event_t e = { .discriminant = FD_VOTOR_POOL_EVENT_SAFE_TO_NOTAR };
  e.inner.safe_to_notar.slot = slot;
  e.inner.safe_to_notar.hash = hash;
  out = fresh_out();
  fd_votor_handle_pool_event( v, &e, &out );

  FD_TEST( count_votes_of_type( &out, FD_VOTE_TYPE_NOTAR_FALLBACK )==1 );
  fd_ag_vote_t const * nf = first_vote_of_type( &out, FD_VOTE_TYPE_NOTAR_FALLBACK );
  FD_TEST( nf && fd_vote_slot( nf )==slot );
  fd_hash_t const * bh = fd_vote_block_hash( nf );
  FD_TEST( bh && !memcmp( bh->uc, hash.uc, sizeof(fd_hash_t) ) );

  fd_votor_delete( fd_votor_leave( v ) );
  fd_wksp_free_laddr( mem );
}

/* safe_to_skip: SafeToSkip -> skip-fallback vote (after we already notar'd). */

static void
test_safe_to_skip( fd_wksp_t * wksp ) {
  create_signers( 2UL );
  fd_votor_out_t out = fresh_out();
  void * mem; fd_votor_t * v = make_votor( wksp, 0UL, &out, &mem );

  ulong slot = 1UL;
  fd_block_id_t parent = genesis_block_id();
  fd_hash_t hash = mk_hash( 0x77 );
  out = fresh_out();
  send_block( v, slot, hash, parent, &out );
  FD_TEST( count_votes_of_type( &out, FD_VOTE_TYPE_NOTAR )==1 );

  /* SafeToSkip(slot) -> skip-fallback */
  fd_votor_pool_event_t e = { .discriminant = FD_VOTOR_POOL_EVENT_SAFE_TO_SKIP };
  e.inner.safe_to_skip = slot;
  out = fresh_out();
  fd_votor_handle_pool_event( v, &e, &out );

  FD_TEST( count_votes_of_type( &out, FD_VOTE_TYPE_SKIP_FALLBACK )==1 );
  fd_ag_vote_t const * sf = first_vote_of_type( &out, FD_VOTE_TYPE_SKIP_FALLBACK );
  FD_TEST( sf && fd_vote_slot( sf )==slot );

  fd_votor_delete( fd_votor_leave( v ) );
  fd_wksp_free_laddr( mem );
}

/* prunes_to_finalized_window: finalizing a mid-window slot drops only the
   slots strictly before its window. */

static void
test_prunes_to_finalized_window( fd_wksp_t * wksp ) {
  create_signers( 2UL );
  fd_votor_out_t out = fresh_out();
  void * mem; fd_votor_t * v = make_votor( wksp, 0UL, &out, &mem );

  ulong finalized    = SPW + 1UL;                              /* not first in its window */
  ulong window_start = fd_alpenglow_first_slot_in_window( finalized );
  FD_TEST( window_start > 0UL );
  FD_TEST( window_start < finalized );

  ulong highest = 2UL*SPW;
  for( ulong i=1UL; i<=highest; i++ ) {
    fd_votor_blockstore_event_t fs = { .discriminant = FD_VOTOR_BLOCKSTORE_EVENT_FIRST_SHRED };
    fs.inner.first_shred = i;
    fd_votor_out_t o2 = fresh_out();
    fd_votor_handle_blockstore_event( v, &fs, &o2 );
  }
  for( ulong i=0UL; i<=highest; i++ ) FD_TEST( fd_votor_slot_state( v, i ) != NULL );

  /* finalize the mid-window slot via a final cert */
  fd_cert_t cert; cert.discriminant = FD_CERT_TYPE_FINAL;
  fd_final_vote_t fvote; fd_final_vote_new( &fvote, finalized, &g_sk[1], 1UL );
  FD_TEST( fd_final_cert_try_new( &cert.inner.final_, &fvote, 1UL, g_info, 2UL )==FD_CERT_SUCCESS );
  fd_votor_pool_event_t cc = { .discriminant = FD_VOTOR_POOL_EVENT_CERT_CREATED };
  cc.inner.cert_created = cert;
  out = fresh_out();
  fd_votor_handle_pool_event( v, &cc, &out );

  FD_TEST( fd_votor_highest_final_cert_slot( v )==finalized );

  /* the whole finalized window is kept */
  for( ulong s=window_start; s<=fd_alpenglow_last_slot_in_window( window_start ); s++ ) {
    FD_TEST( fd_votor_slot_state( v, s ) != NULL );
  }
  /* earlier windows are dropped */
  FD_TEST( fd_votor_slot_state( v, 0UL )==NULL );             /* genesis */
  FD_TEST( fd_votor_slot_state( v, window_start-1UL )==NULL );

  fd_votor_delete( fd_votor_leave( v ) );
  fd_wksp_free_laddr( mem );
}

/* slashing_invariant: after a skip / notar-fallback / skip-fallback for a
   slot, Final is never emitted for it even if a notar cert later arrives. */

static void
test_slashing_invariant( fd_wksp_t * wksp ) {
  create_signers( 2UL );

  /* Case A: skip-fallback after notar.  Even with a notar cert, no final. */
  {
    fd_votor_out_t out = fresh_out();
    void * mem; fd_votor_t * v = make_votor( wksp, 0UL, &out, &mem );
    ulong slot = 1UL;
    fd_block_id_t parent = genesis_block_id();
    fd_hash_t hash = mk_hash( 0x33 );

    out = fresh_out();
    send_block( v, slot, hash, parent, &out );
    FD_TEST( count_votes_of_type( &out, FD_VOTE_TYPE_NOTAR )==1 );

    /* SafeToSkip sets bad_window=1 (slashing invariant) */
    fd_votor_pool_event_t sk = { .discriminant = FD_VOTOR_POOL_EVENT_SAFE_TO_SKIP };
    sk.inner.safe_to_skip = slot;
    out = fresh_out();
    fd_votor_handle_pool_event( v, &sk, &out );
    FD_TEST( fd_votor_slot_state( v, slot )->bad_window );

    /* now a notar cert arrives: try_final must NOT emit a final vote */
    fd_cert_t cert; cert.discriminant = FD_CERT_TYPE_NOTAR;
    fd_notar_vote_t one; fd_notar_vote_new( &one, slot, &hash, &g_sk[0], 0UL );
    FD_TEST( fd_notar_cert_try_new( &cert.inner.notar, &one, 1UL, g_info, 2UL )==FD_CERT_SUCCESS );
    fd_votor_pool_event_t cc = { .discriminant = FD_VOTOR_POOL_EVENT_CERT_CREATED };
    cc.inner.cert_created = cert;
    out = fresh_out();
    fd_votor_handle_pool_event( v, &cc, &out );
    FD_TEST( count_votes_of_type( &out, FD_VOTE_TYPE_FINAL )==0 );

    fd_votor_delete( fd_votor_leave( v ) );
    fd_wksp_free_laddr( mem );
  }

  /* Case B: skip then a (bogus) block + notar cert.  After try_skip_window
     the slot is voted+bad_window, so no notar (already voted) and no final. */
  {
    fd_votor_out_t out = fresh_out();
    void * mem; fd_votor_t * v = make_votor( wksp, 0UL, &out, &mem );
    ulong slot = 1UL;
    fd_hash_t hash = mk_hash( 0x44 );

    /* fire all timeouts -> skip the whole genesis window (incl. slot 1) */
    ulong n_timeouts = out.timeout_cnt;
    fd_votor_timeout_t scheduled[ OUT_TIMEOUT_MAX ];
    for( ulong i=0UL; i<n_timeouts; i++ ) scheduled[i] = out.timeouts[i];
    for( ulong i=0UL; i<n_timeouts; i++ ) {
      fd_votor_out_t o2 = fresh_out();
      fd_votor_handle_timeout_event( v, &scheduled[i], &o2 );
    }
    FD_TEST( fd_votor_slot_state( v, slot )->bad_window );
    FD_TEST( fd_votor_slot_state( v, slot )->voted );

    /* a notar cert for slot now: still no final (bad_window) */
    fd_cert_t cert; cert.discriminant = FD_CERT_TYPE_NOTAR;
    fd_notar_vote_t one; fd_notar_vote_new( &one, slot, &hash, &g_sk[0], 0UL );
    FD_TEST( fd_notar_cert_try_new( &cert.inner.notar, &one, 1UL, g_info, 2UL )==FD_CERT_SUCCESS );
    fd_votor_pool_event_t cc = { .discriminant = FD_VOTOR_POOL_EVENT_CERT_CREATED };
    cc.inner.cert_created = cert;
    out = fresh_out();
    fd_votor_handle_pool_event( v, &cc, &out );
    FD_TEST( count_votes_of_type( &out, FD_VOTE_TYPE_FINAL )==0 );

    fd_votor_delete( fd_votor_leave( v ) );
    fd_wksp_free_laddr( mem );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong       page_cnt = 1UL;
  char *      page_sz  = "gigantic";
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
