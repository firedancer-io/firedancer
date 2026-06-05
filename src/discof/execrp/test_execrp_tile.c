/* test_execrp_tile unit tests replay transaction execution by mocking an
   execrp tile context and using fd_svm_mini for runtime state. */

#include "fd_execrp_tile.c"
#include "../../ballet/txn/fd_txn_build.h"
#include "../../ballet/txn/fd_compact_u16.h"
#include "../../disco/topo/fd_topob.h"
#include "../../flamenco/accdb/fd_accdb.h"
#include "../../flamenco/runtime/tests/fd_svm_mini.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/fd_system_ids_pp.h"
#include "../../flamenco/runtime/program/fd_system_program.h"
#include "../../util/tmpl/fd_unit_test.c"
#include <unistd.h>

#define MAX_LIVE_SLOTS   32
#define MAX_TXN_PER_SLOT 32

#define TOPO_TAG 2UL

int volatile const fd_startup_skip_checks = 1; /* fd_startup.c */

static fd_svm_mini_t * mini;
static fd_topo_t       topo[1];
static uchar           metrics_scratch[ FD_METRICS_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_METRICS_ALIGN)));

struct test_env {
  void *             tile_mem;
  fd_svm_mini_t *    mini;
  fd_execrp_tile_t * execrp;
  ulong              bank_idx;

  void *             allocs[ 16 ];
  ulong              alloc_cnt;
};

typedef struct test_env test_env_t;

static fd_topo_obj_t *
test_topo_obj_laddr( fd_topo_t *  topo,
                     char const * obj_type,
                     char const * wksp_name,
                     void *       laddr ) {
  fd_topo_obj_t * obj = fd_topob_obj( topo, obj_type, wksp_name );
  obj->offset = (ulong)fd_wksp_gaddr_fast( topo->workspaces[ obj->wksp_id ].wksp, laddr );
  return obj;
}

static void
test_topo_link_init( test_env_t *     env,
                     fd_topo_t *      topo,
                     fd_topo_link_t * link ) {
  ulong mcache_footprint = fd_mcache_footprint( link->depth, 0UL );
  void * mcache_mem = fd_wksp_alloc_laddr( env->mini->wksp, fd_mcache_align(), mcache_footprint, TOPO_TAG );
  FD_TEST( fd_mcache_new( mcache_mem, link->depth, 0UL, 0UL ) );
  link->mcache = fd_mcache_join( mcache_mem );
  FD_TEST( link->mcache );
  topo->objs[ link->mcache_obj_id ].offset = fd_wksp_gaddr_fast( env->mini->wksp, mcache_mem );

  if( link->mtu ) {
    ulong data_sz = fd_dcache_req_data_sz( link->mtu, link->depth, link->burst, 1 );
    ulong dcache_footprint = fd_dcache_footprint( data_sz, 0UL );
    void * dcache_mem = fd_wksp_alloc_laddr( env->mini->wksp, fd_dcache_align(), dcache_footprint, TOPO_TAG );
    FD_TEST( fd_dcache_new( dcache_mem, data_sz, 0UL ) );
    link->dcache = fd_dcache_join( dcache_mem );
    FD_TEST( link->dcache );
    topo->objs[ link->dcache_obj_id ].offset = fd_wksp_gaddr_fast( env->mini->wksp, dcache_mem );
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
  test_env_t * env = fd_wksp_alloc_laddr( mini->wksp, alignof(test_env_t), sizeof(test_env_t), TOPO_TAG );
  FD_TEST( env );
  memset( env, 0, sizeof(test_env_t) );

  env->mini = mini;

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong root_idx = fd_svm_mini_reset( env->mini, params );
  env->bank_idx = fd_svm_mini_attach_child( env->mini, root_idx, 2UL );

  fd_topob_new( topo, "execrp" );
  fd_topo_wksp_t * topo_wksp = fd_topob_wksp( topo, "execrp" );
  topo_wksp->wksp = env->mini->wksp;
  fd_topo_tile_t * topo_tile = fd_topob_tile( topo, "execrp", "execrp", "execrp", 0UL, 0, 0, 0 );
  topo_tile->execrp.max_live_slots = MAX_LIVE_SLOTS;

  void * tile_mem = fd_wksp_alloc_laddr( env->mini->wksp, scratch_align(), scratch_footprint( topo_tile ), TOPO_TAG );
  FD_TEST( tile_mem );
  env->tile_mem = tile_mem;
  topo->objs[ topo_tile->tile_obj_id ].offset = fd_wksp_gaddr_fast( env->mini->wksp, tile_mem );

  fd_topo_link_t * replay_execrp = fd_topob_link( topo, "replay_execrp", "execrp", 4UL, sizeof(fd_execrp_task_msg_t),      1UL );
  fd_topo_link_t * execrp_replay = fd_topob_link( topo, "execrp_replay", "execrp", 4UL, sizeof(fd_execrp_task_done_msg_t), 1UL );
  test_topo_link_init( env, topo, replay_execrp );
  test_topo_link_init( env, topo, execrp_replay );
  fd_topob_tile_in ( topo, "execrp", 0UL, "execrp", "replay_execrp", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "execrp", 0UL, "execrp_replay", 0UL );

  /* Share mini's accounts DB with the tile.  The tile re-joins the same
     accdb shmem (a second writer joiner) and opens it via the well-known
     FD_ACCDB_FD_RW fd, so we dup mini's backing memfd onto it. */
  FD_TEST( dup2( env->mini->accdb_fd, FD_ACCDB_FD_RW )==FD_ACCDB_FD_RW );

  fd_topo_obj_t * accdb_obj      = test_topo_obj_laddr( topo, "accdb_shmem", "execrp", env->mini->accdb_shmem_mem );
  fd_topo_obj_t * progcache_obj  = test_topo_obj_laddr( topo, "progcache",  "execrp", env->mini->progcache->join->shmem );
  fd_topo_obj_t * banks_obj      = test_topo_obj_laddr( topo, "banks",      "execrp", env->mini->banks );
  fd_topo_obj_t * txncache_obj   = test_topo_obj_laddr( topo, "txncache",   "execrp", env->mini->txncache_shmem );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

  topo_tile->execrp.accdb_obj_id     = accdb_obj->id;
  topo_tile->execrp.progcache_obj_id = progcache_obj->id;
  topo_tile->execrp.txncache_obj_id  = txncache_obj->id;

  unprivileged_init( topo, topo_tile );

  env->execrp = tile_mem;
  env->execrp->replay_in->mem    = replay_execrp->dcache;
  env->execrp->replay_in->chunk0 = fd_dcache_compact_chunk0( replay_execrp->dcache, replay_execrp->dcache );
  env->execrp->replay_in->wmark  = fd_dcache_compact_wmark ( replay_execrp->dcache, replay_execrp->dcache, replay_execrp->mtu );
  env->execrp->replay_in->chunk  = env->execrp->replay_in->chunk0;

  env->execrp->execrp_replay_out->mem    = execrp_replay->dcache;
  env->execrp->execrp_replay_out->chunk0 = fd_dcache_compact_chunk0( execrp_replay->dcache, execrp_replay->dcache );
  env->execrp->execrp_replay_out->wmark  = fd_dcache_compact_wmark ( execrp_replay->dcache, execrp_replay->dcache, execrp_replay->mtu );
  env->execrp->execrp_replay_out->chunk  = env->execrp->execrp_replay_out->chunk0;
  return env;
}

static void
test_env_destroy( test_env_t * env ) {
  ulong tag = TOPO_TAG;
  fd_wksp_tag_free( env->mini->wksp, &tag, 1UL );
}

#define TEST_CHECKED_ADD_TO_TXN_DATA( _begin, _cur_data, _to_add, _sz ) __extension__({ \
  if( FD_UNLIKELY( (*_cur_data)+(_sz)>(_begin)+FD_TXN_MTU ) ) return ULONG_MAX;         \
  fd_memcpy( *_cur_data, _to_add, (_sz) );                                              \
  *_cur_data += (_sz);                                                                  \
})

#define TEST_CHECKED_ADD_CU16_TO_TXN_DATA( _begin, _cur_data, _to_add ) __extension__({ \
  do {                                                                                  \
    uchar _buf[3];                                                                      \
    ulong _sz = (ulong)fd_cu16_enc( (ushort)(_to_add), _buf );                          \
    TEST_CHECKED_ADD_TO_TXN_DATA( _begin, _cur_data, _buf, _sz );                       \
  } while(0);                                                                           \
})

static ulong
test_txn_serialize_empty( uchar *          txn_raw_begin,
                          fd_signature_t * signature,
                          ulong            readonly_signed_cnt,
                          ulong            readonly_unsigned_cnt,
                          fd_pubkey_t *    account_keys,
                          ulong            account_key_cnt,
                          fd_hash_t const * recent_blockhash ) {
  uchar * txn_raw_cur = txn_raw_begin;

  uchar signature_cnt = 1U;
  TEST_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, &signature_cnt, sizeof(uchar) );
  TEST_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, signature, FD_TXN_SIGNATURE_SZ );

  uchar header_b0 = (uchar)0x80UL;
  TEST_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, &header_b0, sizeof(uchar) );
  TEST_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, &signature_cnt,         sizeof(uchar) );
  TEST_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, &readonly_signed_cnt,   sizeof(uchar) );
  TEST_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, &readonly_unsigned_cnt, sizeof(uchar) );

  TEST_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, account_key_cnt );
  for( ulong i=0UL; i<account_key_cnt; i++ )
    TEST_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, &account_keys[i], sizeof(fd_pubkey_t) );

  TEST_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, recent_blockhash, sizeof(fd_hash_t) );

  ushort instr_cnt = 0U;
  TEST_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, instr_cnt );

  ushort addr_table_cnt = 0U;
  TEST_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, addr_table_cnt );

  return (ulong)( txn_raw_cur - txn_raw_begin );
}

static void
test_build_empty_txn( fd_txn_p_t * out,
                      fd_bank_t *   bank,
                      fd_pubkey_t   fee_payer,
                      fd_pubkey_t   extra_acct,
                      ulong         signature_seed,
                      int           extra_readonly ) {
  fd_signature_t signature = {0};
  signature.ul[0] = signature_seed;

  fd_pubkey_t account_keys[2] = { fee_payer, extra_acct };
  fd_memset( out, 0, sizeof(fd_txn_p_t) );
  fd_hash_t const * recent_blockhash = fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue );
  FD_TEST( recent_blockhash );
  ulong sz = test_txn_serialize_empty( out->payload, &signature, 0UL, (ulong)!!extra_readonly,
                                       account_keys, 2UL, recent_blockhash );
  FD_TEST( sz!=ULONG_MAX );
  FD_TEST( fd_txn_parse( out->payload, sz, TXN( out ), NULL ) );
  out->payload_sz = (ushort)sz;
  out->pack_cu.non_execution_cus                 = 1000U;
  out->pack_cu.requested_exec_plus_acct_data_cus = 300000U;
}

static void
test_build_system_transfer_txn( fd_txn_p_t * out,
                                fd_bank_t *   bank,
                                fd_pubkey_t   from,
                                fd_pubkey_t   to,
                                ulong         lamports ) {
  fd_system_program_instruction_t instr = {
    .discriminant   = FD_SYSTEM_PROGRAM_INSTR_TRANSFER,
    .inner.transfer = lamports
  };
  uchar instr_data[ 16 ];
  ulong instr_data_sz = 0UL;
  FD_TEST( !fd_system_program_instruction_encode( &instr, instr_data, sizeof(instr_data), &instr_data_sz ) );

  fd_hash_t const * recent_blockhash = fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue );
  FD_TEST( recent_blockhash );

  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 2UL ) );
  FD_TEST( fd_txn_builder_fee_payer_set( builder, &from ) );
  fd_txn_builder_blockhash_set( builder, recent_blockhash );
  FD_TEST( fd_txn_builder_instr_open( builder, &fd_solana_system_program_id, instr_data, instr_data_sz ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &from, FD_TXN_ACCT_CAT_WRITABLE | FD_TXN_ACCT_CAT_SIGNER ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &to,   FD_TXN_ACCT_CAT_WRITABLE ) );
  fd_txn_builder_instr_close( builder );

  fd_memset( out, 0, sizeof(fd_txn_p_t) );
  FD_TEST( fd_txn_build_p( builder, out ) );
  out->pack_cu.non_execution_cus                 = 1000U;
  out->pack_cu.requested_exec_plus_acct_data_cus = 300000U;
  fd_txn_builder_delete( builder );
}

static void
test_build_missing_program_txn( fd_txn_p_t * out,
                                fd_bank_t *   bank,
                                fd_pubkey_t   fee_payer,
                                fd_pubkey_t   missing_program ) {
  fd_hash_t const * recent_blockhash = fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue );
  FD_TEST( recent_blockhash );

  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 5UL ) );
  FD_TEST( fd_txn_builder_fee_payer_set( builder, &fee_payer ) );
  fd_txn_builder_blockhash_set( builder, recent_blockhash );
  FD_TEST( fd_txn_builder_instr_open( builder, &missing_program, NULL, 0UL ) );
  fd_txn_builder_instr_close( builder );

  fd_memset( out, 0, sizeof(fd_txn_p_t) );
  FD_TEST( fd_txn_build_p( builder, out ) );
  out->pack_cu.non_execution_cus                 = 1000U;
  out->pack_cu.requested_exec_plus_acct_data_cus = 300000U;
  fd_txn_builder_delete( builder );
}

static void
test_fund_account( test_env_t *        env,
                   fd_pubkey_t const * pubkey,
                   ulong               lamports ) {
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( env->mini, env->bank_idx );
  fd_svm_mini_add_lamports( env->mini, fork_id, pubkey, lamports );
}

static ulong
test_read_lamports( test_env_t *        env,
                    fd_pubkey_t const * pubkey ) {
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( env->mini, env->bank_idx );
  return fd_accdb_lamports( env->mini->runtime->accdb, fork_id, pubkey->uc );
}

static fd_stem_context_t *
test_stem( fd_execrp_tile_t * ctx,
           fd_stem_context_t * stem ) {
  static fd_frag_meta_t * mcaches[FD_TOPO_MAX_LINKS];
  static ulong            seqs[FD_TOPO_MAX_LINKS];
  static ulong            depths[FD_TOPO_MAX_LINKS];
  static ulong            cr_avail[FD_TOPO_MAX_LINKS];
  static ulong            min_cr_avail;
  static int              out_reliable[FD_TOPO_MAX_LINKS];

  fd_topo_link_t const * execrp_replay = test_topo_link( "execrp_replay" );

  memset( mcaches,      0, sizeof(mcaches)      );
  memset( seqs,         0, sizeof(seqs)         );
  memset( depths,       0, sizeof(depths)       );
  memset( out_reliable, 0, sizeof(out_reliable) );
  for( ulong i=0UL; i<FD_TOPO_MAX_LINKS; i++ ) cr_avail[i] = ULONG_MAX;

  mcaches[ ctx->execrp_replay_out->idx ] = execrp_replay->mcache;
  depths [ ctx->execrp_replay_out->idx ] = execrp_replay->depth;
  seqs   [ ctx->execrp_replay_out->idx ] = fd_mcache_seq_query( fd_mcache_seq_laddr_const( mcaches[ ctx->execrp_replay_out->idx ] ) );
  min_cr_avail = ULONG_MAX;

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

static fd_frag_meta_t const *
test_out_meta( ulong seq ) {
  fd_topo_link_t const * execrp_replay = test_topo_link( "execrp_replay" );
  return execrp_replay->mcache + fd_mcache_line_idx( seq, execrp_replay->depth );
}

static fd_execrp_task_done_msg_t const *
test_out_msg( test_env_t *           env,
              fd_frag_meta_t const * meta ) {
  return fd_chunk_to_laddr( env->execrp->execrp_replay_out->mem, meta->chunk );
}

static fd_execrp_task_done_msg_t const *
test_assert_out_msg( test_env_t * env,
                     ulong        seq,
                     ulong        task_type ) {
  fd_frag_meta_t const * meta = test_out_meta( seq );
  FD_TEST( fd_frag_meta_seq_query( meta )==seq );
  FD_TEST( meta->sig==((task_type<<32) | env->execrp->tile_idx) );
  FD_TEST( meta->sz==sizeof(fd_execrp_task_done_msg_t) );
  FD_TEST( meta->chunk>=env->execrp->execrp_replay_out->chunk0 );
  FD_TEST( meta->chunk<=env->execrp->execrp_replay_out->wmark );

  fd_execrp_task_done_msg_t const * out_msg = test_out_msg( env, meta );
  FD_TEST( out_msg->bank_idx==env->bank_idx );
  return out_msg;
}

static fd_execrp_task_done_msg_t const *
test_execrp_run( test_env_t * env,
                 fd_txn_p_t * txn,
                 ulong        txn_idx ) {
  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );
  FD_TEST( bank );

  ulong in_chunk = env->execrp->replay_in->chunk0;
  fd_execrp_txn_exec_msg_t * in_msg = fd_chunk_to_laddr( env->execrp->replay_in->mem, in_chunk );
  fd_memset( in_msg, 0, sizeof(fd_execrp_txn_exec_msg_t) );
  in_msg->bank_idx        = env->bank_idx;
  in_msg->txn_idx         = txn_idx;
  in_msg->capture_txn_idx = txn_idx;
  fd_memcpy( in_msg->txn, txn, sizeof(fd_txn_p_t) );

  fd_stem_context_t stem[1];
  ulong const sig = (FD_EXECRP_TT_TXN_EXEC<<32) | env->execrp->tile_idx;
  FD_TEST( !returnable_frag( env->execrp, env->execrp->replay_in->idx, 0UL, sig, in_chunk,
                             sizeof(fd_execrp_txn_exec_msg_t), 0UL, 0UL,
                             fd_frag_meta_ts_comp( fd_tickcount() ), test_stem( env->execrp, stem ) ) );

  fd_execrp_task_done_msg_t const * out_msg = test_assert_out_msg( env, 0UL, FD_EXECRP_TT_TXN_EXEC );
  FD_TEST( out_msg->txn_exec->txn_idx==txn_idx );
  FD_TEST( out_msg->txn_exec->slot==bank->f.slot );
  return out_msg;
}

FD_UNIT_TEST( execrp_seccomp ) {
  int   out_fds[3];
  ulong nfds = populate_allowed_fds( NULL, NULL, 3UL, out_fds );
  FD_TEST( nfds>=2 && nfds<=3 );
  FD_TEST( out_fds[0]==STDERR_FILENO );
  /* logfile fd is optional; the accounts db fd is always last */
  FD_TEST( out_fds[ nfds-1UL ]==FD_ACCDB_FD_RW );
  if( nfds==3 ) FD_TEST( out_fds[1]==fd_log_private_logfile_fd() );

  struct sock_filter filter[ 32 ];
  populate_allowed_seccomp( NULL, NULL, 32UL, filter );
}

FD_UNIT_TEST( execrp_metrics_write ) {
  test_env_t * env = test_env_create();

  env->execrp->metrics.sigverify_cnt         = 2UL;
  env->execrp->metrics.poh_hash_cnt          = 3UL;
  env->execrp->metrics.txn_load_cum_ticks    = 5UL;
  env->execrp->metrics.txn_check_cum_ticks   = 7UL;
  env->execrp->metrics.txn_exec_cum_ticks    = 11UL;
  env->execrp->metrics.txn_commit_cum_ticks  = 13UL;
  env->execrp->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_SUCCESS_IDX ] = 1UL;
  env->execrp->runtime->metrics.cu_cum       = 17UL;
  env->execrp->runtime->metrics.vm_exec_cum_ticks = 19UL;

  metrics_write( env->execrp );

  test_env_destroy( env );
}

FD_UNIT_TEST( execrp_sigverify ) {
  test_env_t * env = test_env_create();
  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );

  fd_pubkey_t fee_payer = { .ul = { 0x9191UL } };
  fd_pubkey_t data_acct = { .ul = { 0x9292UL } };

  fd_txn_p_t txn[1];
  test_build_empty_txn( txn, bank, fee_payer, data_acct, 91UL, 0 );

  ulong in_chunk = env->execrp->replay_in->chunk0;
  fd_execrp_txn_sigverify_msg_t * in_msg = fd_chunk_to_laddr( env->execrp->replay_in->mem, in_chunk );
  fd_memset( in_msg, 0, sizeof(fd_execrp_txn_sigverify_msg_t) );
  in_msg->bank_idx = env->bank_idx;
  in_msg->txn_idx  = 91UL;
  fd_memcpy( in_msg->txn, txn, sizeof(fd_txn_p_t) );

  fd_stem_context_t stem[1];
  ulong const sig = (FD_EXECRP_TT_TXN_SIGVERIFY<<32) | env->execrp->tile_idx;
  FD_TEST( !returnable_frag( env->execrp, env->execrp->replay_in->idx, 0UL, sig, in_chunk,
                             sizeof(fd_execrp_txn_sigverify_msg_t), 0UL, 0UL, 0UL,
                             test_stem( env->execrp, stem ) ) );

  fd_execrp_task_done_msg_t const * out_msg = test_assert_out_msg( env, 0UL, FD_EXECRP_TT_TXN_SIGVERIFY );
  FD_TEST( out_msg->txn_sigverify->txn_idx==91UL );
  FD_TEST( out_msg->txn_sigverify->err );
  FD_TEST( env->execrp->metrics.sigverify_cnt==TXN(txn)->signature_cnt );

  test_env_destroy( env );
}

FD_UNIT_TEST( execrp_poh_hash ) {
  test_env_t * env = test_env_create();

  ulong in_chunk = env->execrp->replay_in->chunk0;
  fd_execrp_poh_hash_msg_t * in_msg = fd_chunk_to_laddr( env->execrp->replay_in->mem, in_chunk );
  fd_memset( in_msg, 0, sizeof(fd_execrp_poh_hash_msg_t) );
  in_msg->bank_idx = env->bank_idx;
  in_msg->mblk_idx = 92UL;
  in_msg->hashcnt  = 3UL;
  for( ulong i=0UL; i<sizeof(fd_hash_t); i++ ) in_msg->hash->uc[i] = (uchar)i;

  fd_hash_t expected[1];
  fd_sha256_hash_32_repeated( in_msg->hash, expected, in_msg->hashcnt );

  fd_stem_context_t stem[1];
  ulong const sig = (FD_EXECRP_TT_POH_HASH<<32) | env->execrp->tile_idx;
  FD_TEST( !returnable_frag( env->execrp, env->execrp->replay_in->idx, 0UL, sig, in_chunk,
                             sizeof(fd_execrp_poh_hash_msg_t), 0UL, 0UL, 0UL,
                             test_stem( env->execrp, stem ) ) );

  fd_execrp_task_done_msg_t const * out_msg = test_assert_out_msg( env, 0UL, FD_EXECRP_TT_POH_HASH );
  FD_TEST( out_msg->poh_hash->mblk_idx==in_msg->mblk_idx );
  FD_TEST( out_msg->poh_hash->hashcnt ==in_msg->hashcnt  );
  FD_TEST( !memcmp( out_msg->poh_hash->hash, expected, sizeof(fd_hash_t) ) );
  FD_TEST( env->execrp->metrics.poh_hash_cnt==in_msg->hashcnt );

  test_env_destroy( env );
}

FD_UNIT_TEST( execrp_simple_ok ) {
  test_env_t * env = test_env_create();
  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );

  fd_pubkey_t fee_payer = { .ul = { 0x1111UL } };
  fd_pubkey_t recipient = { .ul = { 0x2222UL } };
  ulong const payer_start     = 1000000000UL;
  ulong const recipient_start = 1UL;
  ulong const transfer        = 1234567UL;
  ulong const fee             = 5000UL;

  fd_blockhash_info_t * blockhash_info = (fd_blockhash_info_t *)fd_blockhashes_peek_last( &bank->f.block_hash_queue );
  FD_TEST( blockhash_info );
  blockhash_info->lamports_per_signature = fee;

  test_fund_account( env, &fee_payer, payer_start );
  test_fund_account( env, &recipient, recipient_start );

  fd_txn_p_t txn[1];
  test_build_system_transfer_txn( txn, bank, fee_payer, recipient, transfer );
  fd_execrp_task_done_msg_t const * out_msg = test_execrp_run( env, txn, 18UL );

  FD_TEST( env->execrp->txn_out.err.is_committable );
  FD_TEST( env->execrp->txn_out.err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( out_msg->txn_exec->is_committable );
  FD_TEST( out_msg->txn_exec->txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( test_read_lamports( env, &fee_payer )==payer_start-fee-transfer );
  FD_TEST( test_read_lamports( env, &recipient )==recipient_start+transfer );

  test_env_destroy( env );
}

FD_UNIT_TEST( execrp_simple_fee_payer_fail ) {
  test_env_t * env = test_env_create();
  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );

  fd_pubkey_t missing_fee_payer = { .ul = { 0x3333UL } };
  fd_pubkey_t data_acct         = { .ul = { 0x4444UL } };
  ulong const data_acct_start = 777UL;
  test_fund_account( env, &data_acct, data_acct_start );

  fd_txn_p_t txn[1];
  test_build_empty_txn( txn, bank, missing_fee_payer, data_acct, 12UL, 0 );
  fd_execrp_task_done_msg_t const * out_msg = test_execrp_run( env, txn, 19UL );

  FD_TEST( !env->execrp->txn_out.err.is_committable );
  FD_TEST( env->execrp->txn_out.err.txn_err==FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND );
  FD_TEST( !out_msg->txn_exec->is_committable );
  FD_TEST( out_msg->txn_exec->txn_err==FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND );
  FD_TEST( test_read_lamports( env, &data_acct )==data_acct_start );

  test_env_destroy( env );
}

FD_UNIT_TEST( execrp_simple_error ) {
  test_env_t * env = test_env_create();
  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );

  fd_pubkey_t fee_payer = { .ul = { 0x5151UL } };
  fd_pubkey_t recipient = { .ul = { 0x6262UL } };
  ulong const payer_start     = 1000000UL;
  ulong const recipient_start = 1234UL;
  ulong const fee             = 5000UL;
  ulong const transfer        = payer_start;

  fd_blockhash_info_t * blockhash_info = (fd_blockhash_info_t *)fd_blockhashes_peek_last( &bank->f.block_hash_queue );
  FD_TEST( blockhash_info );
  blockhash_info->lamports_per_signature = fee;

  test_fund_account( env, &fee_payer, payer_start );
  test_fund_account( env, &recipient, recipient_start );

  fd_txn_p_t txn[1];
  test_build_system_transfer_txn( txn, bank, fee_payer, recipient, transfer );
  fd_execrp_task_done_msg_t const * out_msg = test_execrp_run( env, txn, 20UL );

  FD_TEST( env->execrp->txn_out.err.is_committable );
  FD_TEST( !env->execrp->txn_out.err.is_fees_only );
  FD_TEST( env->execrp->txn_out.err.txn_err==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR );
  FD_TEST( out_msg->txn_exec->is_committable );
  FD_TEST( !out_msg->txn_exec->is_fees_only );
  FD_TEST( out_msg->txn_exec->txn_err==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR );
  FD_TEST( test_read_lamports( env, &fee_payer )==payer_start-fee );
  FD_TEST( test_read_lamports( env, &recipient )==recipient_start );

  test_env_destroy( env );
}

FD_UNIT_TEST( execrp_simple_fees_only ) {
  test_env_t * env = test_env_create();
  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );

  fd_pubkey_t fee_payer       = { .ul = { 0x7171UL } };
  fd_pubkey_t missing_program = { .ul = { 0x7272UL } };
  ulong const payer_start = 1000000UL;
  ulong const fee         = 5000UL;

  fd_blockhash_info_t * blockhash_info = (fd_blockhash_info_t *)fd_blockhashes_peek_last( &bank->f.block_hash_queue );
  FD_TEST( blockhash_info );
  blockhash_info->lamports_per_signature = fee;

  test_fund_account( env, &fee_payer, payer_start );

  fd_txn_p_t txn[1];
  test_build_missing_program_txn( txn, bank, fee_payer, missing_program );
  fd_execrp_task_done_msg_t const * out_msg = test_execrp_run( env, txn, 21UL );

  FD_TEST( env->execrp->txn_out.err.is_committable );
  FD_TEST( env->execrp->txn_out.err.is_fees_only );
  FD_TEST( env->execrp->txn_out.err.txn_err==FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND );
  FD_TEST( out_msg->txn_exec->is_committable );
  FD_TEST( out_msg->txn_exec->is_fees_only );
  FD_TEST( out_msg->txn_exec->txn_err==FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND );
  FD_TEST( test_read_lamports( env, &fee_payer )==payer_start-fee );

  test_env_destroy( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  limits->max_live_slots      = MAX_LIVE_SLOTS;
  limits->max_txn_per_slot    = MAX_TXN_PER_SLOT;
  limits->max_txn_write_locks = MAX_TX_ACCOUNT_LOCKS;
  limits->wksp_addl_sz        = 5UL<<30;
  limits->accdb_joiner_cnt    = 2UL; /* mini's runtime join + the exec tile join */

  mini = fd_svm_test_boot( &argc, &argv, limits );
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL ) );

  fd_unit_tests( argc, argv );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
