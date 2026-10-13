/* fd_votor_harness.c drives the votor tile's receive path over a
   sequence of datagrams and emits VotorReceiveEffects to diff against
   Agave (solfuzz-agave votor_receive.rs).

   The tile is included whole so the harness calls the same
   quic_server_datagram_rx production runs.  The validator set is fixed,
   matching Agave's, so fuzzers can sign votes with the same keys on
   both sides.  Our node is not one of the validators, so every
   datagram is external. */

#define FD_TILE_TEST 1
#include "../../../discof/votor/fd_votor_tile.c"

#include "fd_solfuzz_private.h"
#include "fd_votor_harness.h"
#include "generated/votor.pb.h"

#include <stdlib.h>

/* Matches VOTOR_ROOT_SLOT and VOTOR_VALIDATOR_MAX in solfuzz-agave.
   Validator i's identity and compressed BLS key, as Agave derives them
   from its fixed seeds.  The input stakes validators 0..n-1; ranks
   follow from stake. */

#define VOTOR_ROOT_SLOT     (100UL)
#define VOTOR_VALIDATOR_MAX (16UL)

static char const * const votor_id_hex[ VOTOR_VALIDATOR_MAX ] = {
  "5c9c6df261c9cb840475776aaefcd944b405328fab28f9b3a95ef40490d3de84",
  "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
  "204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c21",
  "66cd608b928b88e50e0efeaa33faf1c43cefe07294b0b87e9fe0aba6a3cf7633",
  "20828bf5c5bdcacb684863336c202fb5599da48be5596615742170705beca9f7",
  "d54207da194977dcf46adbfec2bc2e75b52d5a8a42184fedfdc00024f0e3e8da",
  "511c34a1a2cb521df16bb246b8de8e7997ce235c7e76b22a3d7503a24819dd8a",
  "31debe55d37c722768b137131caa6087080b2e0b60b94bd785d14575cfa498bc",
  "53470962558a6e0839022ae65c6b2723b32772e5c0c5f4776cb8e6a3e10ba2f3",
  "31f3322d4923d36c41c109bdb0099193187bed99942096e4926a24c77efd0d2f",
  "64c30815ff26d5c4aff8e11274a38ed6dd0553049da4c10372a9575b7a776909",
  "1e2a137c7fe2279f9d7f0644030a0e9c0b45f781dce71ae4519c0f4384031654",
  "b4088cd3b8962e64a8ac3716fb86fc7e7ae1d025f1eb562155ab663611b2cc28",
  "e8da63a40ca687c87cfce05cb24a786c7e75cc49c70db5573f026f1c6a86ceaa",
  "acdb0e29743f0ccb8686d0a104cb96e05abefec1538765e7595869f7dc8c49aa",
  "43046bfe4092b3e94994eada15dcc20d8aaa07b658fd3954eb8e0efb8bdca5de",
};

static char const * const votor_bls_hex[ VOTOR_VALIDATOR_MAX ] = {
  "97cd03871e2cef7a9f011278de76a9176e1633dad550be23988eef717c1f03391d3a0507e3d340d96bf48476d4a19f9b",
  "922ec1fb34f11237dc7c4987a8c8eab0b9074826106fb5db0952b6885071d77851c53abae9543094574a0eb6fa009d09",
  "a354999e41a77381155d9beb037dd10bec8cff50f4b34a8d35c279979c7401908c0982cb94cf6b7bfccdf91d85ebd28a",
  "99622a2e3199892af1073a6e1ff235cb7d36b37e570cc41cc778367f60877dcb33e9d78b9bd3899110b003d0e2d49020",
  "8526ac95ac555dacb2a5690e353ea81365f005883db4785a967bfa603457bfca9b04abf9eaf5192f0497f4ca926a25ec",
  "9843c4a80be3837440a1afed1e88d0fb8c1c572d8d6535e18f8bf32636cdc52357878d4d3a050803d9b0fe716b0fd749",
  "b90f04d40ba28d78be043ab926517f8bfc9f74ffb265698514f2381e031a4460809a76df542075eddcd9920e35bbb431",
  "b9bf88b66dfd8fc1652b704f028444eab178c8fb0d577949de5a51c83593e7f59c290918d5cc47bc7a534ac9c85b49e4",
  "8c732cd8e447973491d783a9035849b972a5cd91ab4524bae428994e5bd182bea1db6f297f04da39d075c8838ad2b355",
  "b74a3723251f2f8fcd51bf981690fe0fb2c434aba582a931a3ae7c09983e60368b1a5d01c18c84b75b6f351cb57f6bb4",
  "b1eb73741f6ff853c1c29d601dced7d768c81d61c9f7afcfe0c4549abe01fed68d3c0c9439ff390effac0e2a33787aac",
  "aed55d411b43d8e53aa62698e9a377682c665ba0a23f0bb6cb41a12b03d20f670d8e7bf45c5b6fc9de7fed9d9e6c35d7",
  "b59dfe7657f564c084c8a386f875f6a629980317bf3ca5838337988367d7b552fa2390b44d7fc033bf83f8b544e35796",
  "a793c746c34d88d9bc67ba707f043bafff218fcbe7435bed27afb9aba166ef4869ac59f1465337a6f80154af9420461d",
  "a6e046b0adf8406114743eff51a8ab69c5ffe60f3e8749fdb880e505bad03e79bbd2f93e9fc472a7580e5f7d1b758c04",
  "a3ebbb28de27b4bf22951107f55ab37856fd82e4b1e66d8cd72140c0614659df1c1692e53bcd1eb9a3af13cfece94748",
};

/* Pool live slots.  The tile's lookahead bound (VOTE_LOOKAHEAD_MAX)
   is what matches Agave's, so the pool must not reject sooner. */

#define VOTOR_POOL_SLOT_MAX (256UL)

static void
hex_decode( uchar *      out,
            char const * hex,
            ulong        sz ) {
  for( ulong i=0UL; i<sz; i++ ) {
    uint hi = (uint)hex[ 2UL*i     ];
    uint lo = (uint)hex[ 2UL*i+1UL ];
    hi = hi<='9' ? hi-'0' : hi-'a'+10U;
    lo = lo<='9' ? lo-'0' : lo-'a'+10U;
    out[ i ] = (uchar)( (hi<<4) | lo );
  }
}

/* The tile ctx and what it points to, built once per thread.  The
   epoch (ranks), peers (ranks and bans) and the pool are rebuilt per
   input.  ids[ i ] is validator i's identity, as the input indexes
   senders; ids[ VOTOR_VALIDATOR_MAX ] is an unknown sender. */

struct votor_world {
  fd_votor_tile_t ctx;
  fd_pubkey_t     ids[ VOTOR_VALIDATOR_MAX+1UL ];
  uchar           bls[ VOTOR_VALIDATOR_MAX ][ FD_BLS_PUB_COMPRESSED_SZ ];
  fd_quic_conn_t  conns[ VOTOR_VALIDATOR_MAX+1UL ];
  void *          peers_mem;
  void *          pool_mem;
};
typedef struct votor_world votor_world_t;

static FD_TL votor_world_t * votor_world;

static votor_world_t *
votor_world_new( void ) {
  votor_world_t * w = aligned_alloc( alignof(votor_world_t), fd_ulong_align_up( sizeof(votor_world_t), alignof(votor_world_t) ) );
  FD_TEST( w );
  memset( w, 0, sizeof(votor_world_t) );
  fd_votor_tile_t * ctx = &w->ctx;
  fd_clock_tile_init( ctx->clock );
  memset( ctx->id_key.uc, 0xEE, sizeof(fd_pubkey_t) ); /* our identity is not a validator */

  for( ulong i=0UL; i<VOTOR_VALIDATOR_MAX; i++ ) {
    hex_decode( w->ids[ i ].uc, votor_id_hex [ i ], sizeof(fd_pubkey_t)      );
    hex_decode( w->bls[ i ],    votor_bls_hex[ i ], FD_BLS_PUB_COMPRESSED_SZ );
  }
  memset( w->ids[ VOTOR_VALIDATOR_MAX ].uc, 0xAB, sizeof(fd_pubkey_t) );

  /* Each sender's datagrams arrive on its own conn, whose context is
     its identity, as quic_server_conn_new sets it */
  for( ulong i=0UL; i<=VOTOR_VALIDATOR_MAX; i++ ) fd_quic_conn_set_context( &w->conns[ i ], &w->ids[ i ] );

  w->peers_mem = aligned_alloc( peers_align(), fd_ulong_align_up( peers_footprint(), peers_align() ) );
  FD_TEST( w->peers_mem );
  ulong pool_sz = ag_pool_footprint( VOTOR_POOL_SLOT_MAX, QUIC_DGRAM_BURST );
  FD_TEST( pool_sz );
  w->pool_mem = aligned_alloc( ag_pool_align(), fd_ulong_align_up( pool_sz, ag_pool_align() ) );
  FD_TEST( w->pool_mem );
  return w;
}

/* Ranks the input's validators as handle_epoch does, and resets peers
   and the pool.  Returns 0 if the input stakes nobody that ranks. */

static int
votor_world_reset( votor_world_t *                              w,
                   fd_exec_test_votor_receive_context_t const * input ) {
  fd_votor_tile_t * ctx = &w->ctx;
  ulong             cnt = (ulong)input->validator_stakes_count;

  /* Epoch 0 starts at slot 0 and holds the root, as on Agave */
  fd_vote_stake_weight_t stakes[ VOTOR_VALIDATOR_MAX ];
  for( ulong i=0UL; i<cnt; i++ ) {
    memset( &stakes[ i ], 0, sizeof(fd_vote_stake_weight_t) );
    stakes[ i ].id_key   = w->ids[ i ];
    stakes[ i ].vote_key = w->ids[ i ];
    stakes[ i ].stake    = input->validator_stakes[ i ];
    memcpy( stakes[ i ].bls_key, w->bls[ i ], FD_BLS_PUB_COMPRESSED_SZ );
  }
  ctx->curr_epoch_info = rank_voters( &ctx->scratch.curr_epoch_info, stakes, cnt );
  ctx->curr_epoch_slot = 0UL;
  ctx->next_epoch_slot = ULONG_MAX;
  if( FD_UNLIKELY( !ctx->curr_epoch_info->validator_cnt ) ) return 0;

  ctx->peers = peers_join( peers_new( w->peers_mem ) );
  for( ulong rank=0UL; rank<ctx->curr_epoch_info->validator_cnt; rank++ ) {
    fd_pubkey_t id; memcpy( id.uc, ctx->curr_epoch_info->validators[ rank ].id_key, sizeof(fd_pubkey_t) );
    peer_t * peer = peers_insert( ctx->peers, id );
    peer->prev_rank      = USHORT_MAX;
    peer->curr_rank      = (ushort)rank;
    peer->next_rank      = USHORT_MAX;
    peer->tx_conn        = NULL;
    peer->rx_conn        = NULL;
    peer->ban_ts         = LONG_MIN/2L; /* never banned */
    peer->conn_ts        = 0L;
    peer->conn_backoff   = 0L;
    peer->reconn_pending = 0;
  }

  ctx->pool = ag_pool_join( ag_pool_new( w->pool_mem, VOTOR_POOL_SLOT_MAX, QUIC_DGRAM_BURST, 42UL ) );
  FD_TEST( ctx->pool );
  ag_pool_init( ctx->pool, &(ag_block_id_t){ .slot = VOTOR_ROOT_SLOT } );
  ag_pool_advance_epoch( ctx->pool, ctx->curr_epoch_info, USHORT_MAX, 0UL );

  ctx->shred_version             = (ushort)input->shred_version;
  ctx->highest_parent_ready_slot = fd_ulong_max( input->highest_parent_ready_slot, VOTOR_ROOT_SLOT+1UL );
  ctx->init                      = 1;
  memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
  return 1;
}

/* Drains pool events as after_credit does: ParentReady advances
   highest_parent_ready_slot, which bounds the vote lookahead. */

static void
votor_drain_pool_events( fd_votor_tile_t * ctx ) {
  ag_pool_event_t event;
  while( ag_pool_poll_pool_event( ctx->pool, &event ) ) {
    if( FD_UNLIKELY( event.kind==AG_POOL_EVENT_PARENT_READY ) ) ctx->highest_parent_ready_slot = fd_ulong_max( ctx->highest_parent_ready_slot, event.parent_ready.slot );
  }
  ag_block_id_t repair;
  while( ag_pool_poll_repair_event( ctx->pool, &repair ) ) {}
}

/* Base2 bitmap (version 0, bit count, payload) whose bit count is one
   past the highest signer, as the Agave harness normalizes it. */

static pb_size_t
votor_base2_bitmap( fd_bls_set_t const * set,
                    uchar *              out ) {
  ulong cnt = fd_bls_set_is_null( set ) ? 0UL : fd_bls_set_last( set )+1UL;
  ulong sz  = 3UL + (cnt+7UL)/8UL;
  memset( out, 0, sz );
  FD_STORE( ushort, out+1UL, (ushort)cnt );
  for( ulong i=fd_bls_set_const_iter_init( set ); !fd_bls_set_const_iter_done( i ); i=fd_bls_set_const_iter_next( set, i ) ) {
    out[ 3UL+(i>>3) ] |= (uchar)( 1U<<(i&7U) );
  }
  return (pb_size_t)sz;
}

/* Fills a VotorReceiveCert from a cert's signer groups.  The signature is the
   groups' aggregate, as ag_cert_ser puts it on the wire. */

static void
votor_cert_out( fd_exec_test_votor_receive_cert_t * out,
                uint                        kind,
                ulong                       slot,
                uchar const *               block_hash,
                fd_bls_agg_t const *        agg,
                fd_bls_agg_t const *        agg2 ) {
  memset( out, 0, sizeof(*out) );
  out->kind = (fd_exec_test_votor_cert_kind_t)( kind+1U );
  out->slot = slot;
  if( block_hash ) memcpy( out->block_id, block_hash, sizeof(ag_block_hash_t) );
  if( agg2 && fd_bls_set_is_null( agg2->set ) ) agg2 = NULL;
  out->primary_bitmap.size = votor_base2_bitmap( agg->set, out->primary_bitmap.bytes );
  if( agg2 ) out->fallback_bitmap.size = votor_base2_bitmap( agg2->set, out->fallback_bitmap.bytes );
  fd_bls_sig_t sig = agg->sig;
  if( agg2 ) blst_p2_add_or_double( &sig, &sig, &agg2->sig );
  blst_p2_affine sig_aff[1];
  uchar          sig_ser[ FD_BLS_SIG_SZ ];
  blst_p2_to_affine( sig_aff, &sig );
  blst_p2_affine_serialize( sig_ser, sig_aff );
  out->signature_hash = fd_solfuzz_hash( sig_ser, sizeof(sig_ser) );
}

static int
votor_cert_cmp( void const * _a,
                void const * _b ) {
  fd_exec_test_votor_receive_cert_t const * a = _a;
  fd_exec_test_votor_receive_cert_t const * b = _b;
  if( a->kind!=b->kind ) return a->kind<b->kind ? -1 : 1;
  if( a->slot!=b->slot ) return a->slot<b->slot ? -1 : 1;
  return memcmp( a->block_id, b->block_id, sizeof(a->block_id) );
}

ulong
fd_solfuzz_pb_votor_receive_run( fd_solfuzz_runner_t * runner,
                                 void const *          input_,
                                 void **               output_,
                                 void *                output_buf,
                                 ulong                 output_bufsz ) {
  (void)runner;
  fd_exec_test_votor_receive_context_t const * input  = fd_type_pun_const( input_ );
  fd_exec_test_votor_receive_effects_t **      output = fd_type_pun( output_ );

  /* Same scope as the Agave harness */
  if( FD_UNLIKELY( input->shred_version>USHORT_MAX || input->root_slot!=VOTOR_ROOT_SLOT ) ) return 0UL;
  ulong validator_cnt = (ulong)input->validator_stakes_count;
  if( FD_UNLIKELY( !validator_cnt || validator_cnt>VOTOR_VALIDATOR_MAX ) ) return 0UL;
  ulong total_stake = 0UL;
  for( ulong i=0UL; i<validator_cnt; i++ ) {
    ulong stake = input->validator_stakes[ i ];
    if( FD_UNLIKELY( !stake || total_stake+stake<total_stake ) ) return 0UL;
    total_stake += stake;
  }

  if( FD_UNLIKELY( !votor_world ) ) votor_world = votor_world_new();
  votor_world_t *   w   = votor_world;
  if( FD_UNLIKELY( !votor_world_reset( w, input ) ) ) return 0UL;
  fd_votor_tile_t * ctx = &w->ctx;

  ulong datagram_cnt = (ulong)input->datagrams_count;
  ulong cert_max     = VOTOR_POOL_SLOT_MAX*( 4UL+AG_NOTAR_FALLBACK_CERT_MAX );

  ulong output_end = (ulong)output_buf + output_bufsz;
  FD_SCRATCH_ALLOC_INIT( l, output_buf );
  fd_exec_test_votor_receive_effects_t * effects = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_votor_receive_effects_t), sizeof(fd_exec_test_votor_receive_effects_t) );
  bool *                                 results = FD_SCRATCH_ALLOC_APPEND( l, alignof(bool),                                  sizeof(bool)*datagram_cnt                  );
  fd_exec_test_votor_receive_cert_t *    certs   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_test_votor_receive_cert_t),    sizeof(fd_exec_test_votor_receive_cert_t)*cert_max );
  uint *                                 banned  = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                                  sizeof(uint)*VOTOR_VALIDATOR_MAX           );
  if( FD_UNLIKELY( _l>output_end ) ) return 0UL;
  memset( effects, 0, sizeof(*effects) );

  /* A datagram reached the pool if the tile counted it accepted */
  for( ulong i=0UL; i<datagram_cnt; i++ ) {
    fd_exec_test_votor_datagram_t const * dg   = &input->datagrams[ i ];
    fd_quic_conn_t *                      conn = &w->conns[ dg->sender<validator_cnt ? (ulong)dg->sender : VOTOR_VALIDATOR_MAX ];
    ulong vote_ok = ctx->metrics.vote_rx[ FD_METRICS_ENUM_VOTE_RX_RESULT_V_SUCCESS_IDX ];
    ulong cert_ok = ctx->metrics.cert_rx[ FD_METRICS_ENUM_CERT_RX_RESULT_V_SUCCESS_IDX ];
    quic_server_datagram_rx( conn, dg->data.bytes, dg->data.size, ctx );
    results[ i ] = ctx->metrics.vote_rx[ FD_METRICS_ENUM_VOTE_RX_RESULT_V_SUCCESS_IDX ]>vote_ok ||
                   ctx->metrics.cert_rx[ FD_METRICS_ENUM_CERT_RX_RESULT_V_SUCCESS_IDX ]>cert_ok;
    votor_drain_pool_events( ctx );
  }

  /* Certs the pool holds at the end, from every slot it still tracks */
  ulong cert_cnt = 0UL;
  for( ulong slot=fd_ulong_sat_sub( VOTOR_ROOT_SLOT, AG_REWARD_SLOT_DELTA ); slot<VOTOR_ROOT_SLOT+VOTOR_POOL_SLOT_MAX; slot++ ) {
    ag_slot_state_t const * state = ag_pool_slot_state( ctx->pool, slot );
    if( FD_LIKELY( !state ) ) continue;
    ag_slot_certs_t const * c = &state->certs;
    if( c->finalize.slot     !=ULONG_MAX ) votor_cert_out( &certs[ cert_cnt++ ], AG_CERT_KIND_FINAL,      slot, NULL,                        &c->finalize.agg,      NULL );
    if( c->fast_finalize.slot!=ULONG_MAX ) votor_cert_out( &certs[ cert_cnt++ ], AG_CERT_KIND_FAST_FINAL, slot, c->fast_finalize.block_hash, &c->fast_finalize.agg, NULL );
    if( c->notar.slot        !=ULONG_MAX ) votor_cert_out( &certs[ cert_cnt++ ], AG_CERT_KIND_NOTAR,      slot, c->notar.block_hash,         &c->notar.agg,         NULL );
    for( ulong j=0UL; j<c->notar_fallback_cnt; j++ ) {
      ag_cert_notar_fallback_t const * nf = &c->notar_fallback[ j ];
      votor_cert_out( &certs[ cert_cnt++ ], AG_CERT_KIND_NOTAR_FALLBACK, slot, nf->block_hash, &nf->agg_notar, &nf->agg_notar_fallback );
    }
    if( c->skip.slot!=ULONG_MAX ) votor_cert_out( &certs[ cert_cnt++ ], AG_CERT_KIND_SKIP, slot, NULL, &c->skip.agg_skip, &c->skip.agg_skip_fallback );
    FD_TEST( cert_cnt<=cert_max );
  }
  qsort( certs, cert_cnt, sizeof(fd_exec_test_votor_receive_cert_t), votor_cert_cmp );

  ulong banned_cnt = 0UL;
  long  now        = fd_clock_tile_now( ctx->clock );
  for( ulong idx=0UL; idx<validator_cnt; idx++ ) {
    peer_t const * peer = peers_query_const( ctx->peers, w->ids[ idx ], NULL );
    if( peer && now<peer->ban_ts+QUIC_BAN_TIMEOUT_NS ) banned[ banned_cnt++ ] = (uint)idx;
  }

  effects->results_count = (pb_size_t)datagram_cnt;
  effects->results       = results;
  effects->certs_count   = (pb_size_t)cert_cnt;
  effects->certs         = certs;
  effects->banned_count  = (pb_size_t)banned_cnt;
  effects->banned        = banned;

  ag_pool_delete( ag_pool_leave( ctx->pool ) );
  peers_delete( peers_leave( ctx->peers ) );

  ulong actual_end = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  *output = effects;
  return actual_end - (ulong)output_buf;
}
