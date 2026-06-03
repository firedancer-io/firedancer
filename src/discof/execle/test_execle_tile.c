/* test_execle_tile unit tests leader transaction execution by mocking an
   execle tile context and using fd_svm_mini for runtime state.

   The execle tile is mostly the same as the execrp tile, except for
   bundle execution. */

#include "fd_execle_tile.c"
#include "../../ballet/txn/fd_txn_build.h"
#include "../../disco/topo/fd_topob.h"
#include "../../flamenco/accdb/fd_accdb_impl_v1.h"
#include "../../flamenco/runtime/tests/fd_svm_mini.h"
#include "../../flamenco/runtime/fd_system_ids_pp.h"
#include "../../util/tmpl/fd_unit_test.c"
#include <stdlib.h>

#define MAX_LIVE_SLOTS   32
#define MAX_TXN_PER_SLOT 32

int volatile const fd_startup_skip_checks = 1; /* fd_startup.c */

static fd_svm_mini_t * mini;
static fd_topo_t       topo[1];
static uchar           metrics_scratch[ FD_METRICS_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_METRICS_ALIGN)));

struct test_env {
  void *             tile_mem;
  fd_svm_mini_t *    mini;
  fd_execle_tile_t * execle;
  ulong              bank_idx;

  void *             allocs[ 16 ];
  ulong              alloc_cnt;
};

typedef struct test_env test_env_t;

static void
test_mock_validator_keys( fd_pubkey_t * identity_key,
                          fd_pubkey_t * vote_key ) {
  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, 1U, 0UL ) ) );

  for( ulong j=0UL; j<4UL; j++ ) identity_key->ul[j] = fd_rng_ulong( rng );
  for( ulong j=0UL; j<4UL; j++ ) vote_key->ul[j]     = fd_rng_ulong( rng );
  for( ulong j=0UL; j<4UL; j++ ) (void)fd_rng_ulong( rng );

  fd_rng_delete( fd_rng_leave( rng ) );
}

static void *
test_env_alloc( test_env_t * env,
                ulong        align,
                ulong        footprint ) {
  FD_TEST( env->alloc_cnt<sizeof(env->allocs)/sizeof(env->allocs[0]) );
  void * mem = aligned_alloc( align, footprint );
  FD_TEST( mem );
  env->allocs[ env->alloc_cnt++ ] = mem;
  return mem;
}

static void
test_topo_obj_set_laddr( fd_topo_obj_t * obj,
                         void *          laddr ) {
  obj->offset = (ulong)laddr;
}

static fd_topo_obj_t *
test_topo_obj_laddr( fd_topo_t *  topo,
                     char const * obj_type,
                     char const * wksp_name,
                     void *       laddr ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, obj_type, wksp_name );
  test_topo_obj_set_laddr( obj, laddr );
  return obj;
}

static void
test_topo_link_init( test_env_t *    env,
                     fd_topo_t *     topo,
                     fd_topo_link_t * link ) {
  ulong mcache_footprint = fd_mcache_footprint( link->depth, 0UL );
  void * mcache_mem = test_env_alloc( env, fd_mcache_align(), mcache_footprint );
  FD_TEST( fd_mcache_new( mcache_mem, link->depth, 0UL, 0UL ) );
  link->mcache = fd_mcache_join( mcache_mem );
  FD_TEST( link->mcache );
  test_topo_obj_set_laddr( &topo->objs[ link->mcache_obj_id ], mcache_mem );

  if( link->mtu ) {
    ulong data_sz = fd_dcache_req_data_sz( link->mtu, link->depth, link->burst, 1 );
    ulong dcache_footprint = fd_dcache_footprint( data_sz, 0UL );
    void * dcache_mem = test_env_alloc( env, fd_dcache_align(), dcache_footprint );
    FD_TEST( fd_dcache_new( dcache_mem, data_sz, 0UL ) );
    link->dcache = fd_dcache_join( dcache_mem );
    FD_TEST( link->dcache );
    test_topo_obj_set_laddr( &topo->objs[ link->dcache_obj_id ], dcache_mem );
  }
}

static fd_topo_link_t *
test_topo_link( char const * name ) {
  for( ulong i=0UL; i<topo->link_cnt; i++ ) {
    if( !strcmp( topo->links[i].name, name ) ) return &topo->links[i];
  }
  FD_LOG_ERR(( "missing test topo link %s", name ));
}

static test_env_t *
test_env_create( void ) {
  test_env_t * env = aligned_alloc( alignof(test_env_t), sizeof(test_env_t) );
  FD_TEST( env );
  memset( env, 0, sizeof(test_env_t) );

  env->mini = mini;

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong root_idx = fd_svm_mini_reset( env->mini, params );
  env->bank_idx = fd_svm_mini_attach_child( env->mini, root_idx, 2UL );

  fd_topob_new( topo, "execle" );
  fd_topob_wksp( topo, "execle" );
  fd_topo_tile_t * topo_tile = fd_topob_tile( topo, "execle", "execle", "execle", 0UL, 0, 0, 0 );
  topo_tile->execle.max_live_slots = MAX_LIVE_SLOTS;
  topo_tile->execle.accdb_max_depth = MAX_LIVE_SLOTS;

  void * tile_mem = test_env_alloc( env, scratch_align(), scratch_footprint( topo_tile ) );
  env->tile_mem = tile_mem;
  test_topo_obj_set_laddr( &topo->objs[ topo_tile->tile_obj_id ], tile_mem );

  fd_topo_link_t * pack_execle = fd_topob_link( topo, "pack_execle", "execle", 4UL, MAX_MICROBLOCK_SZ, 1UL );
  fd_topo_link_t * execle_poh  = fd_topob_link( topo, "execle_poh",  "execle", 4UL, MAX_MICROBLOCK_SZ, 1UL );
  fd_topo_link_t * execle_pack = fd_topob_link( topo, "execle_pack", "execle", 4UL, MAX_MICROBLOCK_SZ, 1UL );
  test_topo_link_init( env, topo, pack_execle );
  test_topo_link_init( env, topo, execle_poh  );
  test_topo_link_init( env, topo, execle_pack );
  fd_topob_tile_in ( topo, "execle", 0UL, "execle", "pack_execle", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "execle", 0UL, "execle_poh",  0UL );
  fd_topob_tile_out( topo, "execle", 0UL, "execle_pack", 0UL );

  fd_funk_t * funk = fd_accdb_user_v1_funk( env->mini->accdb );
  fd_topo_obj_t * funk_obj       = test_topo_obj_laddr( topo, "funk",       "execle", funk->shmem );
  fd_topo_obj_t * funk_locks_obj = test_topo_obj_laddr( topo, "funk_locks", "execle", (void *)funk->txn_lock );
  fd_topo_obj_t * progcache_obj  = test_topo_obj_laddr( topo, "progcache",  "execle", env->mini->progcache->join->shmem );
  fd_topo_obj_t * banks_obj      = test_topo_obj_laddr( topo, "banks",      "execle", env->mini->banks );
  fd_topo_obj_t * txncache_obj   = test_topo_obj_laddr( topo, "txncache",   "execle", env->mini->txncache_shmem );
  fd_topo_obj_t * acc_pool_obj   = test_topo_obj_laddr( topo, "acc_pool",   "execle", env->mini->acc_pool );
  FD_TEST( fd_pod_insertf_ulong( topo->props, funk_obj->id,       "funk"       ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, funk_locks_obj->id, "funk_locks" ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, progcache_obj->id,  "progcache"  ) );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id,      "banks"      ) );

  void * busy_fseq_mem = test_env_alloc( env, fd_fseq_align(), fd_fseq_footprint() );
  FD_TEST( fd_fseq_new( busy_fseq_mem, 0UL ) );
  fd_topo_obj_t * busy_fseq_obj = test_topo_obj_laddr( topo, "fseq", "execle", busy_fseq_mem );
  FD_TEST( fd_pod_insertf_ulong( topo->props, busy_fseq_obj->id, "execle_busy.%lu", topo_tile->kind_id ) );

  topo_tile->execle.txncache_obj_id = txncache_obj->id;
  topo_tile->execle.acc_pool_obj_id = acc_pool_obj->id;

  unprivileged_init( topo, topo_tile );

  env->execle = tile_mem;
  env->execle->pack_in_mem    = pack_execle->dcache;
  env->execle->pack_in_chunk0 = fd_dcache_compact_chunk0( pack_execle->dcache, pack_execle->dcache );
  env->execle->pack_in_wmark  = fd_dcache_compact_wmark ( pack_execle->dcache, pack_execle->dcache, pack_execle->mtu );

  env->execle->out_poh->mem    = execle_poh->dcache;
  env->execle->out_poh->chunk0 = fd_dcache_compact_chunk0( execle_poh->dcache, execle_poh->dcache );
  env->execle->out_poh->wmark  = fd_dcache_compact_wmark ( execle_poh->dcache, execle_poh->dcache, execle_poh->mtu );
  env->execle->out_poh->chunk  = env->execle->out_poh->chunk0;

  env->execle->out_pack->mem    = execle_pack->dcache;
  env->execle->out_pack->chunk0 = fd_dcache_compact_chunk0( execle_pack->dcache, execle_pack->dcache );
  env->execle->out_pack->wmark  = fd_dcache_compact_wmark ( execle_pack->dcache, execle_pack->dcache, execle_pack->mtu );
  env->execle->out_pack->chunk  = env->execle->out_pack->chunk0;
  return env;
}

static void
test_env_destroy( test_env_t * env ) {
  for( ulong i=env->alloc_cnt; i>0UL; i-- ) free( env->allocs[ i-1UL ] );
  free( env );
}

static void
test_build_vote_txn( fd_txn_p_t * out,
                     fd_bank_t *   bank ) {
  fd_pubkey_t identity_key;
  fd_pubkey_t vote_key;
  test_mock_validator_keys( &identity_key, &vote_key );

  fd_acct_addr_t const vote_prog_id = { .b = { VOTE_PROG_ID } };
  fd_hash_t const *    recent_blockhash    = fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue );
  FD_TEST( recent_blockhash );

  uchar const vote_data[] = {
    0x0e,0x00,0x00,0x00,
  };

  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 1UL ) );
  FD_TEST( fd_txn_builder_fee_payer_set( builder, &identity_key ) );
  fd_txn_builder_blockhash_set( builder, recent_blockhash );
  FD_TEST( fd_txn_builder_instr_open( builder, &vote_prog_id, vote_data, sizeof(vote_data) ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &vote_key,    FD_TXN_ACCT_CAT_WRITABLE ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &identity_key, FD_TXN_ACCT_CAT_SIGNER   ) );
  fd_txn_builder_instr_close( builder );

  fd_memset( out, 0, sizeof(fd_txn_p_t) );
  FD_TEST( fd_txn_build_p( builder, out ) );
  FD_TEST( fd_txn_is_simple_vote_transaction( TXN(out), out->payload ) );
  out->pack_cu.non_execution_cus                 = 1000U;
  out->pack_cu.requested_exec_plus_acct_data_cus = 300000U;
  out->flags = FD_TXN_P_FLAGS_IS_SIMPLE_VOTE;
  fd_txn_builder_delete( builder );
}

static fd_stem_context_t *
test_stem( fd_execle_tile_t * ctx,
           fd_stem_context_t * stem ) {
  static fd_frag_meta_t * mcaches[2];
  static ulong            seqs[2];
  static ulong            depths[2];
  static ulong            cr_avail[2];
  static ulong            min_cr_avail;
  static int              out_reliable[2];

  fd_topo_link_t const * execle_poh  = test_topo_link( "execle_poh"  );
  fd_topo_link_t const * execle_pack = test_topo_link( "execle_pack" );

  mcaches[ ctx->out_poh->idx  ] = execle_poh->mcache;
  mcaches[ ctx->out_pack->idx ] = execle_pack->mcache;
  depths [ ctx->out_poh->idx  ] = execle_poh->depth;
  depths [ ctx->out_pack->idx ] = execle_pack->depth;
  seqs   [ ctx->out_poh->idx  ] = fd_mcache_seq_query( fd_mcache_seq_laddr_const( mcaches[ ctx->out_poh->idx  ] ) );
  seqs   [ ctx->out_pack->idx ] = fd_mcache_seq_query( fd_mcache_seq_laddr_const( mcaches[ ctx->out_pack->idx ] ) );
  cr_avail[0] = cr_avail[1] = ULONG_MAX;
  min_cr_avail = ULONG_MAX;
  out_reliable[0] = out_reliable[1] = 0;

  *stem = (fd_stem_context_t) {
    .mcaches             = mcaches,
    .seqs                = seqs,
    .depths              = depths,
    .cr_avail            = cr_avail,
    .min_cr_avail        = &min_cr_avail,
    .cr_decrement_amount = 1UL,
    .out_reliable        = out_reliable,
  };
  return stem;
}

FD_UNIT_TEST( execle_vote ) {
  test_env_t * env = test_env_create();

  FD_TEST( env->execle->banks==env->mini->banks );
  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );
  FD_TEST( bank );

  ulong in_chunk = env->execle->pack_in_chunk0;
  fd_txn_e_t * in_txn = fd_chunk_to_laddr( env->execle->pack_in_mem, in_chunk );
  test_build_vote_txn( in_txn->txnp, bank );
  fd_memset( in_txn->alt_accts, 0, sizeof(in_txn->alt_accts) );

  fd_microblock_execle_trailer_t * in_trailer = (fd_microblock_execle_trailer_t *)( in_txn+1UL );
  *in_trailer = (fd_microblock_execle_trailer_t) {
    .bank_idx       = env->bank_idx,
    .microblock_idx = 0UL,
    .pack_idx       = 0U,
    .pack_txn_idx   = 0UL,
    .is_bundle      = 0,
  };

  ulong sig = fd_disco_poh_sig( bank->f.slot, POH_PKT_TYPE_MICROBLOCK, env->execle->kind_id );
  ulong sz  = sizeof(fd_txn_e_t) + sizeof(fd_microblock_execle_trailer_t);
  FD_TEST( !before_frag( env->execle, 0UL, 0UL, sig ) );
  during_frag( env->execle, 0UL, 0UL, sig, in_chunk, sz, 0UL );

  fd_stem_context_t stem[1];
  after_frag( env->execle, 0UL, 0UL, sig, sz, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), test_stem( env->execle, stem ) );

  FD_TEST( fd_fseq_query( env->execle->busy_fseq )==0UL );
  fd_topo_link_t const * execle_poh = test_topo_link( "execle_poh" );
  fd_frag_meta_t const * out_poh_mcache = execle_poh->mcache;
  fd_frag_meta_t const * out_poh_meta = out_poh_mcache + fd_mcache_line_idx( 0UL, execle_poh->depth );
  FD_TEST( fd_frag_meta_seq_query( out_poh_meta )==0UL );
  FD_TEST( out_poh_meta->sig==fd_disco_execle_sig( bank->f.slot, 0U ) );
  FD_TEST( out_poh_meta->sz==sizeof(fd_txn_p_t)+sizeof(fd_microblock_trailer_t) );

  fd_txn_p_t const * out_txn = fd_chunk_to_laddr( env->execle->out_poh->mem, out_poh_meta->chunk );
  FD_TEST( out_txn->payload_sz==in_txn->txnp->payload_sz );
  FD_TEST( fd_txn_is_simple_vote_transaction( TXN(out_txn), out_txn->payload ) );
  FD_TEST( env->execle->txn_out[0].err.is_committable );
  FD_TEST( !env->execle->txn_out[0].err.is_fees_only );
  FD_TEST( env->execle->txn_out[0].err.txn_err==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR );
  FD_TEST( (out_txn->flags & FD_TXN_P_FLAGS_RESULT_MASK)==((uint)(-FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR)<<24) );
  FD_TEST( out_txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS );
  FD_TEST( out_txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS );
  FD_TEST( out_txn->execle_cu.actual_consumed_cus + out_txn->execle_cu.rebated_cus ==
           in_txn->txnp->pack_cu.non_execution_cus + in_txn->txnp->pack_cu.requested_exec_plus_acct_data_cus );

  test_env_destroy( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  limits->max_live_slots          = MAX_LIVE_SLOTS;
  limits->max_txn_per_slot        = MAX_TXN_PER_SLOT;
  limits->max_txn_write_locks     = MAX_TX_ACCOUNT_LOCKS;

  mini = fd_svm_test_boot( &argc, &argv, limits );
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL ) );

  fd_unit_tests( argc, argv );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
