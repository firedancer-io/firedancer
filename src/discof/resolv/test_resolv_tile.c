#include "fd_resolv_tile.c"
#include "../../flamenco/runtime/tests/fd_svm_mini.h"
#include "../../ballet/txn/fd_compact_u16.h"
#include "../../util/tmpl/fd_unit_test.c"

#define TOPO_TAG 2UL

static fd_svm_mini_t * mini;
static uchar           metrics_scratch[ FD_METRICS_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_METRICS_ALIGN)));

struct test_env {
  void *            tile_mem;
  fd_svm_mini_t *   mini;
  fd_resolv_ctx_t * ctx;

  fd_stem_context_t stem[1];
  fd_frag_meta_t *  out_mcache[2];
  ulong             stem_seqs[2];
  ulong             stem_depths[2];
  ulong             stem_cr_avail[2];
  ulong             stem_min_cr_avail[1];
  int               out_reliable[2];
  void *            out_dcache[2];
};

typedef struct test_env test_env_t;

struct test_instr {
  uchar   program_id_idx;
  uchar * account_idxs;
  ushort  account_idxs_cnt;
  uchar * data;
  ushort  data_sz;
};

typedef struct test_instr test_instr_t;

static void
test_add( uchar *  begin,
          uchar ** cur,
          void *   data,
          ulong    data_sz ) {
  FD_TEST( *cur+data_sz<=begin+FD_TXN_MTU );
  fd_memcpy( *cur, data, data_sz );
  *cur += data_sz;
}

static void
test_add_cu16( uchar *  begin,
               uchar ** cur,
               ushort   val ) {
  uchar buf[3];
  ulong sz = (ulong)fd_cu16_enc( val, buf );
  test_add( begin, cur, buf, sz );
}

static void
test_serialize_txn( fd_txn_m_t *    txnm,
                    fd_hash_t const * recent_blockhash,
                    fd_pubkey_t *     account_keys,
                    ushort            account_keys_cnt,
                    test_instr_t *    instrs,
                    ushort            instr_cnt ) {
  uchar * begin = fd_txn_m_payload( txnm );
  uchar * cur   = begin;

  uchar signature_cnt = 1U;
  test_add( begin, &cur, &signature_cnt, 1UL );

  fd_signature_t sig = {0};
  test_add( begin, &cur, &sig, sizeof(fd_signature_t) );

  uchar header_b0 = 0x80U; /* v0 transaction */
  uchar req_sigs  = 1U;
  uchar ro_signed = 0U;
  uchar ro_unsig  = 2U;
  test_add( begin, &cur, &header_b0, 1UL );
  test_add( begin, &cur, &req_sigs,  1UL );
  test_add( begin, &cur, &ro_signed, 1UL );
  test_add( begin, &cur, &ro_unsig,  1UL );

  test_add_cu16( begin, &cur, account_keys_cnt );
  for( ushort i=0U; i<account_keys_cnt; i++ ) test_add( begin, &cur, &account_keys[i], sizeof(fd_pubkey_t) );

  test_add( begin, &cur, (void *)recent_blockhash, sizeof(fd_hash_t) );

  test_add_cu16( begin, &cur, instr_cnt );
  for( ushort i=0U; i<instr_cnt; i++ ) {
    test_add( begin, &cur, &instrs[i].program_id_idx, 1UL );
    test_add_cu16( begin, &cur, instrs[i].account_idxs_cnt );
    test_add( begin, &cur, instrs[i].account_idxs, instrs[i].account_idxs_cnt );
    test_add_cu16( begin, &cur, instrs[i].data_sz );
    test_add( begin, &cur, instrs[i].data, instrs[i].data_sz );
  }

  ushort addr_table_cnt = 0U;
  test_add_cu16( begin, &cur, addr_table_cnt );

  txnm->payload_sz = (ushort)( cur-begin );
  txnm->txn_t_sz   = (ushort)fd_txn_parse( fd_txn_m_payload( txnm ), txnm->payload_sz, fd_txn_m_txn_t( txnm ), NULL );
  FD_TEST( txnm->txn_t_sz );
}

static void
test_make_txnm( fd_txn_m_t *    txnm,
                fd_hash_t const * recent_blockhash,
                int              durable_nonce,
                uint             nonce_discriminant,
                ushort           nonce_acct_cnt,
                uchar            program_id_idx ) {
  fd_memset( txnm, 0, FD_TPU_PARSED_MTU );

  fd_pubkey_t keys[4] = {
    { .ul = { 0x1111UL } },
    { .ul = { 0x2222UL } },
    { .ul = { 0x3333UL } },
    { { SYS_PROG_ID } }
  };

  uchar acct_idxs[3] = { 1U, 2U, 0U };
  uint  ix_data      = nonce_discriminant;
  test_instr_t instr = {
    .program_id_idx    = program_id_idx,
    .account_idxs      = acct_idxs,
    .account_idxs_cnt  = nonce_acct_cnt,
    .data              = (uchar *)&ix_data,
    .data_sz           = 4U
  };

  test_serialize_txn( txnm, recent_blockhash, keys, 4U, &instr, (ushort)durable_nonce );
}

static test_env_t *
test_env_create( test_env_t * env ) {
  fd_memset( env, 0, sizeof(test_env_t) );
  env->mini = mini;

  ulong const mcache_depth = 128UL;
  for( ulong i=0UL; i<2UL; i++ ) {
    env->out_mcache[i] = fd_mcache_join( fd_mcache_new(
        fd_wksp_alloc_laddr( mini->wksp, fd_mcache_align(), fd_mcache_footprint( mcache_depth, 0UL ), TOPO_TAG ),
        mcache_depth, 0UL, 0UL ) );
    FD_TEST( env->out_mcache[i] );

    ulong data_sz = fd_dcache_req_data_sz( FD_TPU_PARSED_MTU, mcache_depth, 1UL, 1 );
    env->out_dcache[i] = fd_dcache_join( fd_dcache_new(
        fd_wksp_alloc_laddr( mini->wksp, fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ), TOPO_TAG ),
        data_sz, 0UL ) );
    FD_TEST( env->out_dcache[i] );

    env->stem_seqs[i]     = 0UL;
    env->stem_depths[i]   = mcache_depth;
    env->stem_cr_avail[i] = ULONG_MAX;
    env->out_reliable[i]  = 1;
  }
  env->stem_min_cr_avail[0] = ULONG_MAX;
  *env->stem = (fd_stem_context_t) {
    .mcaches             = env->out_mcache,
    .seqs                = env->stem_seqs,
    .depths              = env->stem_depths,
    .cr_avail            = env->stem_cr_avail,
    .min_cr_avail        = env->stem_min_cr_avail,
    .cr_decrement_amount = 0UL,
    .out_reliable        = env->out_reliable
  };

  env->tile_mem = fd_wksp_alloc_laddr( mini->wksp, scratch_align(), scratch_footprint( NULL ), TOPO_TAG );
  FD_TEST( env->tile_mem );
  FD_SCRATCH_ALLOC_INIT( l, env->tile_mem );
  env->ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_resolv_ctx_t), sizeof(fd_resolv_ctx_t) );
  fd_memset( env->ctx, 0, sizeof(fd_resolv_ctx_t) );

  env->ctx->completed_block_height = 200UL;
  env->ctx->flush_pool_idx         = ULONG_MAX;
  env->ctx->pool                   = pool_join( pool_new( FD_SCRATCH_ALLOC_APPEND( l, pool_align(), pool_footprint( 1UL<<16UL ) ), 1UL<<16UL ) );
  env->ctx->map_chain              = map_chain_join( map_chain_new( FD_SCRATCH_ALLOC_APPEND( l, map_chain_align(), map_chain_footprint( 8192UL ) ), 8192UL, 0UL ) );
  env->ctx->blockhash_map          = map_join( map_new( FD_SCRATCH_ALLOC_APPEND( l, map_align(), map_footprint() ) ) );
  FD_TEST( env->ctx->pool );
  FD_TEST( env->ctx->map_chain );
  FD_TEST( env->ctx->blockhash_map );
  FD_TEST( env->ctx->lru_list==lru_list_join( lru_list_new( env->ctx->lru_list ) ) );

  env->ctx->in[0].kind = IN_KIND_DEDUP;
  env->ctx->in[1].kind = IN_KIND_REPLAY;

  env->ctx->out_pack->mem    = env->out_dcache[0];
  env->ctx->out_pack->chunk0 = 0UL;
  env->ctx->out_pack->wmark  = fd_dcache_compact_wmark( env->out_dcache[0], env->out_dcache[0], FD_TPU_PARSED_MTU );
  env->ctx->out_pack->chunk  = 0UL;

  env->ctx->out_replay->mem    = env->out_dcache[1];
  env->ctx->out_replay->chunk0 = 0UL;
  env->ctx->out_replay->wmark  = fd_dcache_compact_wmark( env->out_dcache[1], env->out_dcache[1], FD_TPU_PARSED_MTU );
  env->ctx->out_replay->chunk  = 0UL;

  return env;
}

static void
test_env_destroy( test_env_t * env ) {
  fd_wksp_free_laddr( env->tile_mem );
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_wksp_free_laddr( fd_mcache_delete( fd_mcache_leave( env->out_mcache[i] ) ) );
    fd_wksp_free_laddr( fd_dcache_delete( fd_dcache_leave( env->out_dcache[i] ) ) );
  }
  fd_memset( env, 0, sizeof(test_env_t) );
}

static void
test_add_blockhash( test_env_t * env,
                    fd_hash_t *  hash,
                    ulong        block_height ) {
  blockhash_map_t * entry = map_insert( env->ctx->blockhash_map, *(blockhash_t *)hash->uc );
  entry->block_height = block_height;
}

static void
test_ingest_txn( test_env_t *     env,
                 fd_hash_t const * recent_blockhash,
                 int               durable_nonce ) {
  fd_txn_m_t * txnm = fd_chunk_to_laddr( env->ctx->out_pack->mem, env->ctx->out_pack->chunk );
  test_make_txnm( txnm, recent_blockhash, durable_nonce, 4U, 3U, 3U );
  after_frag( env->ctx, 0UL, 0UL, 0UL, fd_txn_m_realized_footprint( txnm, 1, 0 ), 0UL, 0UL, env->stem );
}

FD_UNIT_TEST( resolv_is_durable_nonce ) {
  fd_hash_t hash = { .ul = { 0xabcUL } };
  uchar buf[ FD_TPU_PARSED_MTU ] __attribute__((aligned(alignof(fd_txn_m_t))));
  fd_txn_m_t * txnm = (fd_txn_m_t *)buf;

  test_make_txnm( txnm, &hash, 1, 4U, 3U, 3U );
  FD_TEST( fd_resolv_is_durable_nonce( fd_txn_m_txn_t( txnm ), fd_txn_m_payload( txnm ) ) );

  test_make_txnm( txnm, &hash, 0, 4U, 3U, 3U );
  FD_TEST( !fd_resolv_is_durable_nonce( fd_txn_m_txn_t( txnm ), fd_txn_m_payload( txnm ) ) );

  test_make_txnm( txnm, &hash, 1, 5U, 3U, 3U );
  FD_TEST( !fd_resolv_is_durable_nonce( fd_txn_m_txn_t( txnm ), fd_txn_m_payload( txnm ) ) );

  test_make_txnm( txnm, &hash, 1, 4U, 2U, 3U );
  FD_TEST( !fd_resolv_is_durable_nonce( fd_txn_m_txn_t( txnm ), fd_txn_m_payload( txnm ) ) );

  test_make_txnm( txnm, &hash, 1, 4U, 3U, 2U );
  FD_TEST( !fd_resolv_is_durable_nonce( fd_txn_m_txn_t( txnm ), fd_txn_m_payload( txnm ) ) );
}

FD_UNIT_TEST( resolv_durable_nonce_passthrough ) {
  test_env_t env[1];
  test_env_create( env );

  fd_hash_t durable_hash = { .ul = { 0xdeadbeefUL } };
  test_ingest_txn( env, &durable_hash, 1 );

  FD_TEST( env->stem_seqs[0]==1UL );
  FD_TEST( pool_free( env->ctx->pool )==(1UL<<16UL) );
  FD_TEST( env->stem_seqs[0]>0UL );
  fd_frag_meta_t const * meta = env->out_mcache[0] + fd_mcache_line_idx( 0UL, env->stem_depths[0] );
  FD_TEST( meta->seq==0UL );
  FD_TEST( meta->sig==env->ctx->completed_block_height );

  fd_txn_m_t const * published = fd_chunk_to_laddr_const( env->ctx->out_pack->mem, meta->chunk );
  FD_TEST( published->reference_block_height==env->ctx->completed_block_height );

  test_env_destroy( env );
}

FD_UNIT_TEST( resolv_blockhash_unknown ) {
  test_env_t env[1];
  test_env_create( env );

  fd_hash_t hash = { .ul = { 0x12345678UL } };
  test_ingest_txn( env, &hash, 0 );

  FD_TEST( env->stem_seqs[0]==0UL );
  FD_TEST( pool_free( env->ctx->pool )==( (1UL<<16UL)-1UL ) );
  FD_TEST( env->ctx->metrics.stash[ FD_METRICS_ENUM_RESOLVE_STASH_OPERATION_V_INSERTED_IDX ]==1UL );

  env->ctx->_completed_slot_msg.slot = 250UL;
  env->ctx->_completed_slot_msg.block_hash = hash;
  after_frag( env->ctx, 1UL, 0UL, REPLAY_SIG_SLOT_COMPLETED, sizeof(fd_replay_slot_completed_t), 0UL, 0UL, env->stem );

  int opt_poll_in = 1;
  int charge_busy = 0;
  after_credit( env->ctx, env->stem, &opt_poll_in, &charge_busy );

  FD_TEST( env->stem_seqs[0]==1UL );
  FD_TEST( pool_free( env->ctx->pool )==(1UL<<16UL) );
  FD_TEST( env->ctx->metrics.stash[ FD_METRICS_ENUM_RESOLVE_STASH_OPERATION_V_PUBLISHED_IDX ]==1UL );
  FD_TEST( env->stem_seqs[0]>0UL );
  fd_frag_meta_t const * meta = env->out_mcache[0] + fd_mcache_line_idx( 0UL, env->stem_depths[0] );
  FD_TEST( meta->seq==0UL );
  FD_TEST( meta->sig==250UL );

  fd_txn_m_t const * published = fd_chunk_to_laddr_const( env->ctx->out_pack->mem, meta->chunk );
  FD_TEST( published->reference_block_height==250UL );

  test_env_destroy( env );
}

FD_UNIT_TEST( resolv_blockhash_known ) {
  test_env_t env[1];
  test_env_create( env );

  fd_hash_t hash = { .ul = { 0xfeedUL } };
  test_add_blockhash( env, &hash, 125UL );
  test_ingest_txn( env, &hash, 0 );

  FD_TEST( env->stem_seqs[0]==1UL );
  FD_TEST( env->stem_seqs[0]>0UL );
  fd_frag_meta_t const * meta = env->out_mcache[0] + fd_mcache_line_idx( 0UL, env->stem_depths[0] );
  FD_TEST( meta->seq==0UL );
  FD_TEST( meta->sig==125UL );

  fd_txn_m_t const * published = fd_chunk_to_laddr_const( env->ctx->out_pack->mem, meta->chunk );
  FD_TEST( published->reference_block_height==125UL );

  test_env_destroy( env );
}

FD_UNIT_TEST( resolv_blockhash_expired ) {
  test_env_t env[1];
  test_env_create( env );
  env->ctx->root_block_height = 300UL;

  fd_hash_t hash = { .ul = { 0xbeadUL } };
  test_add_blockhash( env, &hash, 100UL );
  test_ingest_txn( env, &hash, 0 );

  FD_TEST( env->stem_seqs[0]==0UL );
  FD_TEST( env->ctx->metrics.blockhash_expired==1UL );

  test_env_destroy( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  limits->max_live_slots      = 32;
  limits->max_txn_per_slot    = 32;
  limits->max_txn_write_locks = MAX_TX_ACCOUNT_LOCKS;
  limits->wksp_addl_sz        = 5UL<<30;

  mini = fd_svm_test_boot( &argc, &argv, limits );
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL ) );

  fd_unit_tests( argc, argv );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
