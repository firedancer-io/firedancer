/* test_execle_tile unit tests leader transaction execution by mocking an
   execle tile context and using fd_svm_mini for runtime state.

   The execle tile is mostly the same as the execrp tile, except for
   bundle execution. */

#define _GNU_SOURCE
#include "fd_execle_tile.c"
#include "../../ballet/txn/fd_txn_build.h"
#include "../../disco/topo/fd_topob.h"
#include "../../flamenco/accdb/fd_accdb.h"
#include "../../flamenco/runtime/tests/fd_svm_mini.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/fd_system_ids_pp.h"
#include "../../flamenco/runtime/program/fd_system_program.h"
#include "../../flamenco/runtime/program/fd_bpf_loader_program.h"
#include "../../flamenco/runtime/program/vote/fd_vote_codec.h"
#include "../../ballet/txn/fd_compact_u16.h"
#include "../../util/tmpl/fd_unit_test.c"
#include <unistd.h>

#define MAX_LIVE_SLOTS   32
#define MAX_TXN_PER_SLOT 32

#define TOPO_TAG 2UL

int volatile const fd_startup_skip_checks = 1; /* fd_startup.c */

static fd_svm_mini_t * mini;
static fd_topo_t       topo[1];
static uchar           metrics_scratch[ FD_METRICS_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_METRICS_ALIGN)));

FD_IMPORT_BINARY( test_bpf_program, "src/ballet/sbpf/fixtures/hello_solana_program.so" );

struct test_env {
  void *             tile_mem;
  fd_svm_mini_t *    mini;
  fd_execle_tile_t * execle;
  ulong              bank_idx;
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

  fd_topob_new( topo, "execle" );
  fd_topo_wksp_t * topo_wksp = fd_topob_wksp( topo, "execle" );
  topo_wksp->wksp = env->mini->wksp;
  fd_topo_tile_t * topo_tile = fd_topob_tile( topo, "execle", "execle", "execle", 0UL, 0, 0, 0 );
  topo_tile->execle.max_live_slots = MAX_LIVE_SLOTS;

  void * tile_mem = fd_wksp_alloc_laddr( env->mini->wksp, scratch_align(), scratch_footprint( topo_tile ), TOPO_TAG );
  FD_TEST( tile_mem );
  env->tile_mem = tile_mem;
  topo->objs[ topo_tile->tile_obj_id ].offset = fd_wksp_gaddr_fast( env->mini->wksp, tile_mem );

  fd_topo_link_t * pack_execle = fd_topob_link( topo, "pack_execle", "execle", 4UL, MAX_MICROBLOCK_SZ, 1UL );
  fd_topo_link_t * execle_poh  = fd_topob_link( topo, "execle_poh",  "execle", 4UL, MAX_MICROBLOCK_SZ, 1UL );
  fd_topo_link_t * execle_pack = fd_topob_link( topo, "execle_pack", "execle", 4UL, MAX_MICROBLOCK_SZ, 1UL );
  test_topo_link_init( env, topo, pack_execle );
  test_topo_link_init( env, topo, execle_poh  );
  test_topo_link_init( env, topo, execle_pack );
  fd_topob_tile_in ( topo, "execle", 0UL, "execle", "pack_execle", 0UL, FD_TOPOB_RELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( topo, "execle", 0UL, "execle_poh",  0UL );
  fd_topob_tile_out( topo, "execle", 0UL, "execle_pack", 0UL );

  /* Share mini's accounts DB with the tile.  The tile re-joins the same
     accdb shmem (a second writer joiner) and opens it via the well-known
     FD_ACCDB_FD_RW fd, so we dup mini's backing memfd onto it. */
  FD_TEST( dup2( env->mini->accdb_fd, FD_ACCDB_FD_RW )==FD_ACCDB_FD_RW );

  fd_topo_obj_t * accdb_obj      = test_topo_obj_laddr( topo, "accdb_shmem", "execle", env->mini->accdb_shmem_mem );
  fd_topo_obj_t * progcache_obj  = test_topo_obj_laddr( topo, "progcache",  "execle", env->mini->progcache->join->shmem );
  fd_topo_obj_t * banks_obj      = test_topo_obj_laddr( topo, "banks",      "execle", env->mini->banks );
  fd_topo_obj_t * txncache_obj   = test_topo_obj_laddr( topo, "txncache",   "execle", env->mini->txncache_shmem );
  FD_TEST( fd_pod_insertf_ulong( topo->props, banks_obj->id, "banks" ) );

  void * busy_fseq_mem = fd_wksp_alloc_laddr( env->mini->wksp, fd_fseq_align(), fd_fseq_footprint(), TOPO_TAG );
  FD_TEST( fd_fseq_new( busy_fseq_mem, 0UL ) );
  fd_topo_obj_t * busy_fseq_obj = test_topo_obj_laddr( topo, "fseq", "execle", busy_fseq_mem );
  FD_TEST( fd_pod_insertf_ulong( topo->props, busy_fseq_obj->id, "execle_busy.%lu", topo_tile->kind_id ) );

  topo_tile->execle.accdb_obj_id     = accdb_obj->id;
  topo_tile->execle.progcache_obj_id = progcache_obj->id;
  topo_tile->execle.txncache_obj_id  = txncache_obj->id;

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
  ulong tag = TOPO_TAG;
  fd_wksp_tag_free( env->mini->wksp, &tag, 1UL );
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

static void
test_build_vote_authorize_txn( fd_txn_p_t * out,
                               fd_bank_t *   bank ) {
  fd_pubkey_t identity_key;
  fd_pubkey_t vote_key;
  test_mock_validator_keys( &identity_key, &vote_key );

  fd_pubkey_t new_authority = { .ul = { 0xa17a0UL } };
  fd_acct_addr_t const vote_prog_id = { .b = { VOTE_PROG_ID } };
  fd_hash_t const * recent_blockhash = fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue );
  FD_TEST( recent_blockhash );

  uchar instr_data[ 40UL ];
  uint discriminant = fd_vote_instruction_enum_authorize;
  uint authorization_type = fd_vote_authorize_enum_voter;
  fd_memcpy( instr_data,       &discriminant,       sizeof(uint) );
  fd_memcpy( instr_data+4UL,   &new_authority,      sizeof(fd_pubkey_t) );
  fd_memcpy( instr_data+36UL,  &authorization_type, sizeof(uint) );

  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 2UL ) );
  FD_TEST( fd_txn_builder_fee_payer_set( builder, &identity_key ) );
  fd_txn_builder_blockhash_set( builder, recent_blockhash );
  FD_TEST( fd_txn_builder_instr_open( builder, &vote_prog_id, instr_data, sizeof(instr_data) ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &vote_key,        FD_TXN_ACCT_CAT_WRITABLE ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &fd_sysvar_clock_id, 0U ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &identity_key,    FD_TXN_ACCT_CAT_SIGNER   ) );
  fd_txn_builder_instr_close( builder );

  fd_memset( out, 0, sizeof(fd_txn_p_t) );
  FD_TEST( fd_txn_build_p( builder, out ) );
  FD_TEST( fd_txn_is_simple_vote_transaction( TXN(out), out->payload ) );
  out->pack_cu.non_execution_cus                 = 1000U;
  out->pack_cu.requested_exec_plus_acct_data_cus = 300000U;
  out->flags = FD_TXN_P_FLAGS_IS_SIMPLE_VOTE;
  fd_txn_builder_delete( builder );
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
  FD_TEST( readonly_signed_cnt  <=(ulong)UCHAR_MAX );
  FD_TEST( readonly_unsigned_cnt<=(ulong)UCHAR_MAX );
  uchar header_readonly_signed_cnt   = (uchar)readonly_signed_cnt;
  uchar header_readonly_unsigned_cnt = (uchar)readonly_unsigned_cnt;

  TEST_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, &signature_cnt, sizeof(uchar) );
  TEST_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, signature, FD_TXN_SIGNATURE_SZ );

  uchar header_b0 = (uchar)0x80UL;
  TEST_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, &header_b0, sizeof(uchar) );
  TEST_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, &signature_cnt, sizeof(uchar) );
  TEST_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, &header_readonly_signed_cnt, sizeof(uchar) );
  TEST_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur, &header_readonly_unsigned_cnt, sizeof(uchar) );

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
test_build_empty_txn( fd_txn_p_t *    out,
                      fd_bank_t *      bank,
                      fd_pubkey_t      fee_payer,
                      fd_pubkey_t      extra_acct,
                      ulong            signature_seed,
                      int              extra_readonly ) {
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

FD_FN_UNUSED static void
test_durable_nonce_from_blockhash( fd_hash_t *       out,
                                   fd_hash_t const * blockhash ) {
  uchar buf[ 13UL + sizeof(fd_hash_t) ];
  fd_memcpy( buf,      "DURABLE_NONCE", 13UL );
  fd_memcpy( buf+13UL, blockhash,       sizeof(fd_hash_t) );
  fd_sha256_hash( buf, sizeof(buf), out );
}

FD_FN_UNUSED static void
test_build_durable_nonce_transfer_txn( fd_txn_p_t *    out,
                                       fd_pubkey_t      fee_payer,
                                       fd_pubkey_t      nonce_key,
                                       fd_pubkey_t      recipient,
                                       fd_hash_t const * durable_nonce,
                                       ulong            lamports,
                                       ulong            seed ) {
  fd_system_program_instruction_t instr = {
    .discriminant   = FD_SYSTEM_PROGRAM_INSTR_TRANSFER,
    .inner.transfer = lamports
  };
  uchar instr_data[ 16 ];
  ulong instr_data_sz = 0UL;
  FD_TEST( !fd_system_program_instruction_encode( &instr, instr_data, sizeof(instr_data), &instr_data_sz ) );

  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, seed ) );
  FD_TEST( fd_txn_builder_fee_payer_set( builder, &fee_payer ) );
  fd_txn_builder_blockhash_set( builder, durable_nonce );
  FD_TEST( fd_txn_builder_nonce_set( builder, &nonce_key, &fee_payer ) );
  FD_TEST( fd_txn_builder_instr_open( builder, &fd_solana_system_program_id, instr_data, instr_data_sz ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &fee_payer, FD_TXN_ACCT_CAT_WRITABLE | FD_TXN_ACCT_CAT_SIGNER ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &recipient, FD_TXN_ACCT_CAT_WRITABLE ) );
  fd_txn_builder_instr_close( builder );

  fd_memset( out, 0, sizeof(fd_txn_p_t) );
  FD_TEST( fd_txn_build_p( builder, out ) );
  out->pack_cu.non_execution_cus                 = 1000U;
  out->pack_cu.requested_exec_plus_acct_data_cus = 300000U;
  out->flags = FD_TXN_P_FLAGS_DURABLE_NONCE;
  fd_txn_builder_delete( builder );
}

FD_FN_UNUSED static void
test_build_bpf_close_txn( fd_txn_p_t * out,
                          fd_bank_t *   bank,
                          fd_pubkey_t   authority,
                          fd_pubkey_t   recipient,
                          fd_pubkey_t   program,
                          fd_pubkey_t   programdata ) {
  fd_bpf_instruction_t instr = { .discriminant = FD_BPF_INSTR_CLOSE };
  uchar instr_data[ 4 ];
  ulong instr_data_sz = 0UL;
  FD_TEST( !fd_bpf_instruction_encode( &instr, instr_data, sizeof(instr_data), &instr_data_sz ) );

  fd_hash_t const * recent_blockhash = fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue );
  FD_TEST( recent_blockhash );

  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 3UL ) );
  FD_TEST( fd_txn_builder_fee_payer_set( builder, &authority ) );
  fd_txn_builder_blockhash_set( builder, recent_blockhash );
  FD_TEST( fd_txn_builder_instr_open( builder, &fd_solana_bpf_loader_upgradeable_program_id, instr_data, instr_data_sz ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &programdata, FD_TXN_ACCT_CAT_WRITABLE ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &recipient,   FD_TXN_ACCT_CAT_WRITABLE ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &authority,   FD_TXN_ACCT_CAT_SIGNER   ) );
  FD_TEST( fd_txn_builder_instr_account_push( builder, &program,     FD_TXN_ACCT_CAT_WRITABLE ) );
  fd_txn_builder_instr_close( builder );

  fd_memset( out, 0, sizeof(fd_txn_p_t) );
  FD_TEST( fd_txn_build_p( builder, out ) );
  out->pack_cu.non_execution_cus                 = 1000U;
  out->pack_cu.requested_exec_plus_acct_data_cus = 300000U;
  fd_txn_builder_delete( builder );
}

FD_FN_UNUSED static void
test_build_program_invoke_txn( fd_txn_p_t * out,
                               fd_bank_t *   bank,
                               fd_pubkey_t   fee_payer,
                               fd_pubkey_t   program ) {
  fd_hash_t const * recent_blockhash = fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue );
  FD_TEST( recent_blockhash );

  fd_txn_builder_t builder[1];
  FD_TEST( fd_txn_builder_new( builder, 4UL ) );
  FD_TEST( fd_txn_builder_fee_payer_set( builder, &fee_payer ) );
  fd_txn_builder_blockhash_set( builder, recent_blockhash );
  FD_TEST( fd_txn_builder_instr_open( builder, &program, NULL, 0UL ) );
  fd_txn_builder_instr_close( builder );

  fd_memset( out, 0, sizeof(fd_txn_p_t) );
  FD_TEST( fd_txn_build_p( builder, out ) );
  out->pack_cu.non_execution_cus                 = 1000U;
  out->pack_cu.requested_exec_plus_acct_data_cus = 300000U;
  fd_txn_builder_delete( builder );
}

static void
test_fund_account( test_env_t *          env,
                   fd_pubkey_t const *   pubkey,
                   ulong                 lamports ) {
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( env->mini, env->bank_idx );
  fd_svm_mini_add_lamports( env->mini, fork_id, pubkey, lamports );
}

static void
test_put_account_rooted( test_env_t *        env,
                         fd_pubkey_t const * pubkey,
                         fd_pubkey_t const * owner,
                         ulong               lamports,
                         ulong               slot,
                         int                 executable,
                         uchar const *       data,
                         ulong               data_sz ) {
  (void)slot;
  fd_acc_t acc = {0};
  fd_memcpy( acc.pubkey, pubkey, sizeof(fd_pubkey_t) );
  fd_memcpy( acc.owner,  owner,  sizeof(fd_pubkey_t) );
  acc.lamports   = lamports;
  acc.executable = !!executable;
  acc.data_len   = data_sz;
  acc.data       = (uchar *)data;
  fd_svm_mini_put_account_rooted( env->mini, &acc );
}

FD_FN_UNUSED static void
test_put_nonce_account_rooted( test_env_t *        env,
                               fd_pubkey_t const * nonce_key,
                               fd_pubkey_t const * authority,
                               fd_hash_t const *   durable_nonce,
                               ulong               lamports ) {
  fd_nonce_state_versions_t state = {
    .version       = FD_NONCE_VERSION_CURRENT,
    .kind          = FD_NONCE_STATE_INITIALIZED,
    .authority     = *authority,
    .durable_nonce = *durable_nonce,
  };
  uchar data[ FD_SYSTEM_PROGRAM_NONCE_DLEN ] = {0};
  ulong written = 0UL;
  FD_TEST( !fd_nonce_state_versions_encode( &state, data, FD_SYSTEM_PROGRAM_NONCE_DLEN, &written ) );
  test_put_account_rooted( env, nonce_key, &fd_solana_system_program_id, lamports, 0UL, 0,
                           data, FD_SYSTEM_PROGRAM_NONCE_DLEN );
}

static ulong
test_read_lamports( test_env_t *        env,
                    fd_pubkey_t const * pubkey ) {
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( env->mini, env->bank_idx );
  return fd_accdb_lamports( env->mini->runtime->accdb, fork_id, pubkey->uc );
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

static void
test_execle_run( test_env_t *     env,
                 fd_txn_p_t *     txns,
                 ulong            txn_cnt,
                 uint             pack_idx,
                 ulong            pack_txn_idx,
                 int              is_bundle ) {
  FD_TEST( txn_cnt<=MAX_TXN_PER_SLOT );

  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );
  FD_TEST( bank );

  ulong in_chunk = env->execle->pack_in_chunk0;
  fd_txn_e_t * in_txn = fd_chunk_to_laddr( env->execle->pack_in_mem, in_chunk );
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_memset( &in_txn[i], 0, sizeof(fd_txn_e_t) );
    fd_memcpy( in_txn[i].txnp, &txns[i], sizeof(fd_txn_p_t) );
    if( is_bundle ) in_txn[i].txnp->flags |= FD_TXN_P_FLAGS_BUNDLE;
  }

  fd_microblock_execle_trailer_t * in_trailer = (fd_microblock_execle_trailer_t *)( in_txn+txn_cnt );
  *in_trailer = (fd_microblock_execle_trailer_t) {
    .bank_idx       = env->bank_idx,
    .microblock_idx = 0UL,
    .pack_idx       = pack_idx,
    .pack_txn_idx   = pack_txn_idx,
    .is_bundle      = is_bundle,
  };

  ulong sig = fd_disco_poh_sig( bank->f.slot, POH_PKT_TYPE_MICROBLOCK, env->execle->kind_id );
  ulong sz  = txn_cnt*sizeof(fd_txn_e_t) + sizeof(fd_microblock_execle_trailer_t);
  FD_TEST( !before_frag( env->execle, 0UL, 0UL, sig ) );
  during_frag( env->execle, 0UL, 0UL, sig, in_chunk, sz, 0UL );

  fd_stem_context_t stem[1];
  after_frag( env->execle, 0UL, 0UL, sig, sz, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), test_stem( env->execle, stem ) );
  FD_TEST( fd_fseq_query( env->execle->busy_fseq )==0UL );
}

static fd_frag_meta_t const *
test_out_poh_meta( ulong seq ) {
  fd_topo_link_t const * execle_poh = test_topo_link( "execle_poh" );
  return execle_poh->mcache + fd_mcache_line_idx( seq, execle_poh->depth );
}

FD_FN_UNUSED static fd_frag_meta_t const *
test_out_pack_meta( ulong seq ) {
  fd_topo_link_t const * execle_pack = test_topo_link( "execle_pack" );
  return execle_pack->mcache + fd_mcache_line_idx( seq, execle_pack->depth );
}

static void
test_assert_nonbundle_out( test_env_t * env,
                           ulong        txn_cnt,
                           uint         pack_idx ) {
  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );
  fd_frag_meta_t const * meta = test_out_poh_meta( 0UL );
  FD_TEST( fd_frag_meta_seq_query( meta )==0UL );
  FD_TEST( meta->sig==fd_disco_execle_sig( bank->f.slot, pack_idx ) );
  FD_TEST( meta->sz==txn_cnt*sizeof(fd_txn_p_t)+sizeof(fd_microblock_trailer_t) );
}

static void
test_assert_bundle_out( test_env_t * env,
                        ulong        txn_cnt,
                        uint         pack_idx ) {
  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_frag_meta_t const * meta = test_out_poh_meta( i );
    FD_TEST( fd_frag_meta_seq_query( meta )==i );
    FD_TEST( meta->sig==fd_disco_execle_sig( bank->f.slot, pack_idx+(uint)i ) );
    FD_TEST( meta->sz==sizeof(fd_txn_p_t)+sizeof(fd_microblock_trailer_t) );
  }
}

static fd_microblock_trailer_t const *
test_out_poh_trailer_nonbundle( test_env_t * env,
                                ulong        txn_cnt ) {
  fd_frag_meta_t const * meta = test_out_poh_meta( 0UL );
  fd_txn_p_t const * txns = fd_chunk_to_laddr( env->execle->out_poh->mem, meta->chunk );
  return (fd_microblock_trailer_t const *)( txns + txn_cnt );
}

static fd_microblock_trailer_t const *
test_out_poh_trailer_bundle( test_env_t * env,
                             ulong        seq ) {
  fd_frag_meta_t const * meta = test_out_poh_meta( seq );
  fd_txn_p_t const * txns = fd_chunk_to_laddr( env->execle->out_poh->mem, meta->chunk );
  return (fd_microblock_trailer_t const *)( txns + 1UL );
}

static void
test_compute_expected_hash( fd_txn_p_t * txns,
                            ulong        txn_cnt,
                            uchar        expected_hash[32] ) {
  uchar bmtree_mem[ FD_BMTREE_COMMIT_FOOTPRINT(0) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  FD_TEST( hash_transactions( bmtree_mem, txns, txn_cnt, expected_hash )==expected_hash );
}

FD_UNIT_TEST( execle_hash_transactions_no_executed_txn ) {
  fd_txn_p_t txn[1];
  txn->flags = 0U;

  uchar bmtree_mem[ FD_BMTREE_COMMIT_FOOTPRINT(0) ] __attribute__((aligned(FD_BMTREE_COMMIT_ALIGN)));
  uchar mixin[32];
  FD_TEST( !hash_transactions( bmtree_mem, txn, 1UL, mixin ) );
}

static void
test_assert_txn_ns_dt_ordered( fd_txn_ns_dt_t const * dt ) {
  FD_TEST( dt->load_start   >= 0.f );
  FD_TEST( dt->check_start  >= dt->load_start   );
  FD_TEST( dt->exec_start   >= dt->check_start  );
  FD_TEST( dt->commit_start >= dt->exec_start   );
  FD_TEST( dt->commit_end   >= dt->commit_start );
}

FD_UNIT_TEST( execle_seccomp ) {
  int   out_fds[3];
  ulong nfds = populate_allowed_fds( NULL, NULL, 3UL, out_fds );
  FD_TEST( nfds>=2 && nfds<=3 );
  FD_TEST( out_fds[0]==STDERR_FILENO );
  /* logfile fd is optional; the accounts db fd is always last */
  FD_TEST( out_fds[ nfds-1UL ]==FD_ACCDB_FD_RW );
  if( nfds==3 ) FD_TEST( out_fds[1]==fd_log_private_logfile_fd() );

  struct sock_filter filter[ sock_filter_policy_fd_execle_tile_instr_cnt ];
  populate_allowed_seccomp( NULL, NULL, sock_filter_policy_fd_execle_tile_instr_cnt, filter );
}

FD_UNIT_TEST( execle_vote ) {
  /* Simple vote transaction */
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
  FD_TEST( out_txn->execle_cu.actual_consumed_cus==(uint)FD_PACK_FIXED_SIMPLE_VOTE_COST );

  fd_microblock_trailer_t const * trailer = test_out_poh_trailer_nonbundle( env, 1UL );
  FD_TEST( trailer->pack_txn_idx==0UL );
  FD_TEST( trailer->tips==0UL );
  fd_txn_p_t txn_copy = *out_txn;
  uchar expected_hash[32];
  test_compute_expected_hash( &txn_copy, 1UL, expected_hash );
  FD_TEST( !memcmp( trailer->hash, expected_hash, 32UL ) );
  test_assert_txn_ns_dt_ordered( &trailer->txn_ns_dt );

  FD_TEST( env->execle->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_LANDED_FAILED_IDX ]==1UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_INSTRUCTION_ERROR_IDX ]==1UL );

  test_env_destroy( env );
}

FD_UNIT_TEST( execle_bundle_vote_authorize ) {
  /* Simple vote transaction in a bundle */
  test_env_t * env = test_env_create();
  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );
  FD_TEST( bank );

  fd_txn_p_t txn[1];
  test_build_vote_authorize_txn( txn, bank );
  test_execle_run( env, txn, 1UL, 2U, 16UL, 1 );

  test_assert_bundle_out( env, 1UL, 2U );
  fd_txn_p_t const * out_txn = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( 0UL )->chunk );
  FD_TEST( fd_txn_is_simple_vote_transaction( TXN(out_txn), out_txn->payload ) );
  FD_TEST( env->execle->txn_out[0].err.is_committable );
  FD_TEST( env->execle->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( out_txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS );
  FD_TEST( out_txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS );
  FD_TEST( out_txn->execle_cu.actual_consumed_cus==(uint)FD_PACK_FIXED_SIMPLE_VOTE_COST );
  FD_TEST( out_txn->execle_cu.rebated_cus==
           txn->pack_cu.non_execution_cus + txn->pack_cu.requested_exec_plus_acct_data_cus - (uint)FD_PACK_FIXED_SIMPLE_VOTE_COST );
  FD_TEST( !env->execle->txn_out[0].err.is_fees_only );

  fd_microblock_trailer_t const * trailer = test_out_poh_trailer_bundle( env, 0UL );
  FD_TEST( trailer->pack_txn_idx==16UL );
  FD_TEST( trailer->tips==0UL );
  fd_txn_p_t txn_copy = *out_txn;
  uchar expected_hash[32];
  test_compute_expected_hash( &txn_copy, 1UL, expected_hash );
  FD_TEST( !memcmp( trailer->hash, expected_hash, 32UL ) );
  test_assert_txn_ns_dt_ordered( &trailer->txn_ns_dt );

  FD_TEST( env->execle->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_LANDED_SUCCESS_IDX ]==1UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_SUCCESS_IDX ]==1UL );

  test_env_destroy( env );
}

FD_UNIT_TEST( execle_simple_ok ) {
  /* Simple system program transfer */
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
  test_execle_run( env, txn, 1UL, 3U, 17UL, 0 );

  test_assert_nonbundle_out( env, 1UL, 3U );
  fd_txn_p_t const * out_txn = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( 0UL )->chunk );
  FD_TEST( env->execle->txn_out[0].err.is_committable );
  FD_TEST( env->execle->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( out_txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS );
  FD_TEST( out_txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS );
  FD_TEST( (out_txn->flags & FD_TXN_P_FLAGS_RESULT_MASK)==0U );
  FD_TEST( test_read_lamports( env, &fee_payer )==payer_start-fee-transfer );
  FD_TEST( test_read_lamports( env, &recipient )==recipient_start+transfer );
  FD_TEST( !env->execle->txn_out[0].err.is_fees_only );

  FD_TEST( out_txn->execle_cu.actual_consumed_cus + out_txn->execle_cu.rebated_cus ==
           txn->pack_cu.non_execution_cus + txn->pack_cu.requested_exec_plus_acct_data_cus );
  FD_TEST( out_txn->execle_cu.actual_consumed_cus >= txn->pack_cu.non_execution_cus );

  fd_microblock_trailer_t const * trailer = test_out_poh_trailer_nonbundle( env, 1UL );
  FD_TEST( trailer->pack_txn_idx==17UL );
  FD_TEST( trailer->tips==0UL );
  fd_txn_p_t txn_copy = *out_txn;
  uchar expected_hash[32];
  test_compute_expected_hash( &txn_copy, 1UL, expected_hash );
  FD_TEST( !memcmp( trailer->hash, expected_hash, 32UL ) );
  test_assert_txn_ns_dt_ordered( &trailer->txn_ns_dt );

  FD_TEST( env->execle->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_LANDED_SUCCESS_IDX ]==1UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_SUCCESS_IDX ]==1UL );

  test_env_destroy( env );
}

FD_UNIT_TEST( execle_simple_fee_payer_fail ) {
  /* Transaction failed */
  test_env_t * env = test_env_create();
  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );

  fd_pubkey_t missing_fee_payer = { .ul = { 0x3333UL } };
  fd_pubkey_t data_acct         = { .ul = { 0x4444UL } };
  ulong const data_acct_start = 777UL;
  test_fund_account( env, &data_acct, data_acct_start );

  fd_txn_p_t txn[1];
  test_build_empty_txn( txn, bank, missing_fee_payer, data_acct, 12UL, 0 );
  test_execle_run( env, txn, 1UL, 4U, 18UL, 0 );

  test_assert_nonbundle_out( env, 1UL, 4U );
  fd_txn_p_t const * out_txn = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( 0UL )->chunk );
  FD_TEST( !env->execle->txn_out[0].err.is_committable );
  FD_TEST( env->execle->txn_out[0].err.txn_err==FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND );
  FD_TEST( !(out_txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS) );
  FD_TEST( !(out_txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) );
  FD_TEST( (out_txn->flags & FD_TXN_P_FLAGS_RESULT_MASK)==((uint)(-FD_RUNTIME_TXN_ERR_ACCOUNT_NOT_FOUND)<<24) );
  FD_TEST( test_read_lamports( env, &data_acct )==data_acct_start );

  FD_TEST( out_txn->execle_cu.actual_consumed_cus==0U );
  FD_TEST( out_txn->execle_cu.rebated_cus==
           txn->pack_cu.non_execution_cus + txn->pack_cu.requested_exec_plus_acct_data_cus );

  fd_microblock_trailer_t const * trailer = test_out_poh_trailer_nonbundle( env, 1UL );
  FD_TEST( trailer->pack_txn_idx==18UL );
  FD_TEST( trailer->tips==0UL );
  /* hash not checked: empty bmtree (no EXECUTE_SUCCESS txns) */
  FD_TEST( trailer->txn_ns_dt.load_start  ==0.f );
  FD_TEST( trailer->txn_ns_dt.check_start ==0.f );
  FD_TEST( trailer->txn_ns_dt.exec_start  ==0.f );
  FD_TEST( trailer->txn_ns_dt.commit_start==0.f );
  FD_TEST( trailer->txn_ns_dt.commit_end  ==0.f );

  FD_TEST( env->execle->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_UNLANDED_IDX ]==1UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_ACCOUNT_NOT_FOUND_IDX ]==1UL );

  test_env_destroy( env );
}

FD_UNIT_TEST( execle_simple_error ) {
  /* System transfer fails during execution */
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
  test_execle_run( env, txn, 1UL, 5U, 19UL, 0 );

  test_assert_nonbundle_out( env, 1UL, 5U );
  fd_txn_p_t const * out_txn = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( 0UL )->chunk );
  FD_TEST( env->execle->txn_out[0].err.is_committable );
  FD_TEST( !env->execle->txn_out[0].err.is_fees_only );
  FD_TEST( env->execle->txn_out[0].err.txn_err==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR );
  FD_TEST( (out_txn->flags & FD_TXN_P_FLAGS_RESULT_MASK)==((uint)(-FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR)<<24) );
  FD_TEST( out_txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS );
  FD_TEST( out_txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS );
  FD_TEST( test_read_lamports( env, &fee_payer )==payer_start-fee );
  FD_TEST( test_read_lamports( env, &recipient )==recipient_start );

  FD_TEST( out_txn->execle_cu.actual_consumed_cus + out_txn->execle_cu.rebated_cus ==
           txn->pack_cu.non_execution_cus + txn->pack_cu.requested_exec_plus_acct_data_cus );
  FD_TEST( out_txn->execle_cu.actual_consumed_cus >= txn->pack_cu.non_execution_cus );

  fd_microblock_trailer_t const * trailer = test_out_poh_trailer_nonbundle( env, 1UL );
  FD_TEST( trailer->pack_txn_idx==19UL );
  FD_TEST( trailer->tips==0UL );
  fd_txn_p_t txn_copy = *out_txn;
  uchar expected_hash[32];
  test_compute_expected_hash( &txn_copy, 1UL, expected_hash );
  FD_TEST( !memcmp( trailer->hash, expected_hash, 32UL ) );
  test_assert_txn_ns_dt_ordered( &trailer->txn_ns_dt );

  FD_TEST( env->execle->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_LANDED_FAILED_IDX ]==1UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_INSTRUCTION_ERROR_IDX ]==1UL );

  test_env_destroy( env );
}

FD_UNIT_TEST( execle_simple_fees_only ) {
  /* Account loading fails after fees are validated */
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
  test_execle_run( env, txn, 1UL, 6U, 20UL, 0 );

  test_assert_nonbundle_out( env, 1UL, 6U );
  fd_txn_p_t const * out_txn = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( 0UL )->chunk );
  FD_TEST( env->execle->txn_out[0].err.is_committable );
  FD_TEST( env->execle->txn_out[0].err.is_fees_only );
  FD_TEST( env->execle->txn_out[0].err.txn_err==FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND );
  FD_TEST( (out_txn->flags & FD_TXN_P_FLAGS_RESULT_MASK)==((uint)(-FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND)<<24) );
  FD_TEST( out_txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS );
  FD_TEST( out_txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS );
  FD_TEST( out_txn->execle_cu.actual_consumed_cus + out_txn->execle_cu.rebated_cus ==
           txn->pack_cu.non_execution_cus + txn->pack_cu.requested_exec_plus_acct_data_cus );
  FD_TEST( env->execle->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_LANDED_FEES_ONLY_IDX ]==1UL );
  FD_TEST( test_read_lamports( env, &fee_payer )==payer_start-fee );
  FD_TEST( out_txn->execle_cu.actual_consumed_cus >= txn->pack_cu.non_execution_cus );

  fd_microblock_trailer_t const * trailer = test_out_poh_trailer_nonbundle( env, 1UL );
  FD_TEST( trailer->pack_txn_idx==20UL );
  FD_TEST( trailer->tips==0UL );
  fd_txn_p_t txn_copy = *out_txn;
  uchar expected_hash[32];
  test_compute_expected_hash( &txn_copy, 1UL, expected_hash );
  FD_TEST( !memcmp( trailer->hash, expected_hash, 32UL ) );
  test_assert_txn_ns_dt_ordered( &trailer->txn_ns_dt );

  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_PROGRAM_ACCOUNT_NOT_FOUND_IDX ]==1UL );

  test_env_destroy( env );
}

/* Multi-transaction bundle tests.  Bundle execution forwards account
   state between txns through prev_txn_outs (the new accdb defers account
   release to commit/cancel time); see handle_bundle() in the tile and
   fd_runtime_commit_txn / fd_runtime_cancel_txn in fd_runtime.c. */
FD_UNIT_TEST( execle_bundle_ok ) {
  /* Successful bundle */
  test_env_t * env = test_env_create();
  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );

  fd_pubkey_t fee_payer  = { .ul = { 0x5555UL } };
  fd_pubkey_t recipient0 = { .ul = { 0x6666UL } };
  fd_pubkey_t recipient1 = { .ul = { 0x6667UL } };
  ulong const fee              = 5000UL;
  ulong const payer_start      = 1000000000UL;
  ulong const recipient0_start = 111UL;
  ulong const recipient1_start = 222UL;
  ulong const transfer0        = 1234567UL;
  ulong const transfer1        = 7654321UL;

  fd_blockhash_info_t * blockhash_info = (fd_blockhash_info_t *)fd_blockhashes_peek_last( &bank->f.block_hash_queue );
  FD_TEST( blockhash_info );
  blockhash_info->lamports_per_signature = fee;

  test_fund_account( env, &fee_payer,  payer_start );
  test_fund_account( env, &recipient0, recipient0_start );
  test_fund_account( env, &recipient1, recipient1_start );

  fd_txn_p_t txns[2];
  test_build_system_transfer_txn( &txns[0], bank, fee_payer, recipient0, transfer0 );
  test_build_system_transfer_txn( &txns[1], bank, fee_payer, recipient1, transfer1 );
  test_execle_run( env, txns, 2UL, 8U, 21UL, 1 );

  test_assert_bundle_out( env, 2UL, 8U );
  FD_TEST( env->execle->txn_out[0].err.is_committable );
  FD_TEST( env->execle->txn_out[1].err.is_committable );
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_txn_p_t const * out_txn = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( i )->chunk );
    FD_TEST( out_txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS );
    FD_TEST( out_txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS );
    FD_TEST( (out_txn->flags & FD_TXN_P_FLAGS_RESULT_MASK)==0U );
    FD_TEST( !env->execle->txn_out[i].err.is_fees_only );
    FD_TEST( env->execle->txn_out[i].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );

    FD_TEST( out_txn->execle_cu.actual_consumed_cus + out_txn->execle_cu.rebated_cus ==
             txns[i].pack_cu.non_execution_cus + txns[i].pack_cu.requested_exec_plus_acct_data_cus );
    FD_TEST( out_txn->execle_cu.actual_consumed_cus >= txns[i].pack_cu.non_execution_cus );

    fd_microblock_trailer_t const * trailer = test_out_poh_trailer_bundle( env, i );
    FD_TEST( trailer->pack_txn_idx==21UL+i );
    FD_TEST( trailer->tips==0UL );
    fd_txn_p_t txn_copy = *out_txn;
    uchar expected_hash[32];
    test_compute_expected_hash( &txn_copy, 1UL, expected_hash );
    FD_TEST( !memcmp( trailer->hash, expected_hash, 32UL ) );
    test_assert_txn_ns_dt_ordered( &trailer->txn_ns_dt );
  }

  FD_TEST( test_read_lamports( env, &fee_payer  )==payer_start - 2UL*fee - transfer0 - transfer1 );
  FD_TEST( test_read_lamports( env, &recipient0 )==recipient0_start + transfer0 );
  FD_TEST( test_read_lamports( env, &recipient1 )==recipient1_start + transfer1 );

  FD_TEST( env->execle->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_LANDED_SUCCESS_IDX ]==2UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_SUCCESS_IDX ]==2UL );

  test_env_destroy( env );
}

FD_UNIT_TEST( execle_bundle_fail ) {
  /* Instruction in a bundle reverts the whole bundle */
  test_env_t * env = test_env_create();
  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );

  fd_pubkey_t fee_payer  = { .ul = { 0x7777UL } };
  fd_pubkey_t recipient0 = { .ul = { 0x8888UL } };
  fd_pubkey_t recipient1 = { .ul = { 0x9999UL } };
  ulong const fee              = 5000UL;
  ulong const payer_start      = 1000000000UL;
  ulong const recipient0_start = 111UL;
  ulong const recipient1_start = 222UL;
  ulong const first_transfer   = 100000000UL;
  ulong const second_transfer  = payer_start;

  fd_blockhash_info_t * blockhash_info = (fd_blockhash_info_t *)fd_blockhashes_peek_last( &bank->f.block_hash_queue );
  FD_TEST( blockhash_info );
  blockhash_info->lamports_per_signature = fee;

  test_fund_account( env, &fee_payer,  payer_start );
  test_fund_account( env, &recipient0, recipient0_start );
  test_fund_account( env, &recipient1, recipient1_start );

  fd_txn_p_t txns[2];
  test_build_system_transfer_txn( &txns[0], bank, fee_payer, recipient0, first_transfer );
  test_build_system_transfer_txn( &txns[1], bank, fee_payer, recipient1, second_transfer );
  test_execle_run( env, txns, 2UL, 12U, 31UL, 1 );

  test_assert_bundle_out( env, 2UL, 12U );
  FD_TEST( env->execle->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( env->execle->txn_out[1].err.txn_err==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR );
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_txn_p_t const * out_txn = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( i )->chunk );
    FD_TEST( !env->execle->txn_out[i].err.is_committable );
    FD_TEST( !(out_txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS) );
    FD_TEST( !(out_txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) );

    FD_TEST( out_txn->execle_cu.actual_consumed_cus==0U );
    FD_TEST( out_txn->execle_cu.rebated_cus==
             txns[i].pack_cu.requested_exec_plus_acct_data_cus + txns[i].pack_cu.non_execution_cus );

    fd_microblock_trailer_t const * trailer = test_out_poh_trailer_bundle( env, i );
    FD_TEST( trailer->pack_txn_idx==31UL+i );
    FD_TEST( trailer->tips==0UL );
    /* hash not checked: empty bmtree (no EXECUTE_SUCCESS txns) */
  }

  fd_txn_p_t const * out_txn0 = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( 0UL )->chunk );
  fd_txn_p_t const * out_txn1 = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( 1UL )->chunk );
  FD_TEST( (out_txn0->flags & FD_TXN_P_FLAGS_RESULT_MASK)==((uint)(-FD_RUNTIME_TXN_ERR_BUNDLE_PEER)<<24) );
  FD_TEST( (out_txn1->flags & FD_TXN_P_FLAGS_RESULT_MASK)==((uint)(-FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR)<<24) );

  fd_frag_meta_t const * rebate_meta = test_out_pack_meta( 0UL );
  FD_TEST( fd_frag_meta_seq_query( rebate_meta )==0UL );
  FD_TEST( rebate_meta->sig==bank->f.slot );
  FD_TEST( rebate_meta->sz>=FD_PACK_REBATE_MIN_SZ );
  fd_pack_rebate_t const * rebate = fd_chunk_to_laddr( env->execle->out_pack->mem, rebate_meta->chunk );
  ulong expected_rebated_cus = 0UL;
  ulong expected_data_bytes  = 2UL*48UL;
  for( ulong i=0UL; i<2UL; i++ ) {
    expected_rebated_cus += txns[i].pack_cu.requested_exec_plus_acct_data_cus + txns[i].pack_cu.non_execution_cus;
    expected_data_bytes  += txns[i].payload_sz;
  }
  FD_TEST( rebate->total_cost_rebate    ==expected_rebated_cus );
  FD_TEST( rebate->data_bytes_rebate    ==expected_data_bytes  );
  FD_TEST( rebate->microblock_cnt_rebate==2UL                  );
  FD_TEST( rebate->alloc_rebate         ==0UL                  );
  FD_TEST( rebate->ib_result            ==0                    );

  FD_TEST( test_read_lamports( env, &fee_payer  )==payer_start      );
  FD_TEST( test_read_lamports( env, &recipient0 )==recipient0_start );
  FD_TEST( test_read_lamports( env, &recipient1 )==recipient1_start );

  FD_TEST( env->execle->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_UNLANDED_IDX ]==2UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_INSTRUCTION_ERROR_IDX ]==1UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_BUNDLE_PEER_IDX ]==1UL );

  test_env_destroy( env );
}

FD_UNIT_TEST( execle_bundle_peer_fail ) {
  /* A middle transaction failure skips the rest of the bundle. */
  test_env_t * env = test_env_create();
  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );

  fd_pubkey_t fee_payer  = { .ul = { 0x7979UL } };
  fd_pubkey_t recipient0 = { .ul = { 0x8989UL } };
  fd_pubkey_t recipient1 = { .ul = { 0x9998UL } };
  fd_pubkey_t recipient2 = { .ul = { 0xa9a9UL } };
  ulong const fee              = 5000UL;
  ulong const payer_start      = 1000000000UL;
  ulong const recipient0_start = 111UL;
  ulong const recipient1_start = 222UL;
  ulong const recipient2_start = 333UL;
  ulong const first_transfer   = 100000000UL;
  ulong const second_transfer  = payer_start;
  ulong const third_transfer   = 1UL;

  fd_blockhash_info_t * blockhash_info = (fd_blockhash_info_t *)fd_blockhashes_peek_last( &bank->f.block_hash_queue );
  FD_TEST( blockhash_info );
  blockhash_info->lamports_per_signature = fee;

  test_fund_account( env, &fee_payer,  payer_start );
  test_fund_account( env, &recipient0, recipient0_start );
  test_fund_account( env, &recipient1, recipient1_start );
  test_fund_account( env, &recipient2, recipient2_start );

  fd_txn_p_t txns[3];
  test_build_system_transfer_txn( &txns[0], bank, fee_payer, recipient0, first_transfer  );
  test_build_system_transfer_txn( &txns[1], bank, fee_payer, recipient1, second_transfer );
  test_build_system_transfer_txn( &txns[2], bank, fee_payer, recipient2, third_transfer  );
  test_execle_run( env, txns, 3UL, 14U, 35UL, 1 );

  test_assert_bundle_out( env, 3UL, 14U );
  FD_TEST( env->execle->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( env->execle->txn_out[1].err.txn_err==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR );
  FD_TEST( env->execle->txn_out[2].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( env->execle->txn_out[2].details.load_start_ticks  ==LONG_MAX );
  FD_TEST( env->execle->txn_out[2].details.check_start_ticks ==LONG_MAX );
  FD_TEST( env->execle->txn_out[2].details.exec_start_ticks  ==LONG_MAX );
  FD_TEST( env->execle->txn_out[2].details.commit_start_ticks==LONG_MAX );

  for( ulong i=0UL; i<3UL; i++ ) {
    fd_txn_p_t const * out_txn = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( i )->chunk );
    FD_TEST( !env->execle->txn_out[i].err.is_committable );
    FD_TEST( !(out_txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS) );
    FD_TEST( !(out_txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) );

    FD_TEST( out_txn->execle_cu.actual_consumed_cus==0U );
    FD_TEST( out_txn->execle_cu.rebated_cus==
             txns[i].pack_cu.requested_exec_plus_acct_data_cus + txns[i].pack_cu.non_execution_cus );

    fd_microblock_trailer_t const * trailer = test_out_poh_trailer_bundle( env, i );
    FD_TEST( trailer->pack_txn_idx==35UL+i );
    FD_TEST( trailer->tips==0UL );
    /* hash not checked: empty bmtree (no EXECUTE_SUCCESS txns) */
  }

  /* Txns 0 and 1 were executed, ordering invariant holds */
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_microblock_trailer_t const * trailer = test_out_poh_trailer_bundle( env, i );
    test_assert_txn_ns_dt_ordered( &trailer->txn_ns_dt );
  }
  /* Txn 2 was never executed, all zeros */
  {
    fd_microblock_trailer_t const * trailer = test_out_poh_trailer_bundle( env, 2UL );
    FD_TEST( trailer->txn_ns_dt.load_start  ==0.f );
    FD_TEST( trailer->txn_ns_dt.check_start ==0.f );
    FD_TEST( trailer->txn_ns_dt.exec_start  ==0.f );
    FD_TEST( trailer->txn_ns_dt.commit_start==0.f );
    FD_TEST( trailer->txn_ns_dt.commit_end  ==0.f );
  }

  fd_txn_p_t const * out_txn0 = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( 0UL )->chunk );
  fd_txn_p_t const * out_txn1 = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( 1UL )->chunk );
  fd_txn_p_t const * out_txn2 = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( 2UL )->chunk );
  FD_TEST( (out_txn0->flags & FD_TXN_P_FLAGS_RESULT_MASK)==((uint)(-FD_RUNTIME_TXN_ERR_BUNDLE_PEER)<<24) );
  FD_TEST( (out_txn1->flags & FD_TXN_P_FLAGS_RESULT_MASK)==((uint)(-FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR)<<24) );
  FD_TEST( (out_txn2->flags & FD_TXN_P_FLAGS_RESULT_MASK)==((uint)(-FD_RUNTIME_TXN_ERR_BUNDLE_PEER)<<24) );
  FD_TEST( out_txn0->flags & FD_TXN_P_FLAGS_BUNDLE );
  FD_TEST( out_txn1->flags & FD_TXN_P_FLAGS_BUNDLE );
  FD_TEST( out_txn2->flags & FD_TXN_P_FLAGS_BUNDLE );

  fd_frag_meta_t const * rebate_meta = test_out_pack_meta( 0UL );
  FD_TEST( fd_frag_meta_seq_query( rebate_meta )==0UL );
  FD_TEST( rebate_meta->sig==bank->f.slot );
  FD_TEST( rebate_meta->sz>=FD_PACK_REBATE_MIN_SZ );
  fd_pack_rebate_t const * rebate = fd_chunk_to_laddr( env->execle->out_pack->mem, rebate_meta->chunk );
  ulong expected_rebated_cus = 0UL;
  ulong expected_data_bytes  = 3UL*48UL;
  for( ulong i=0UL; i<3UL; i++ ) {
    expected_rebated_cus += txns[i].pack_cu.requested_exec_plus_acct_data_cus + txns[i].pack_cu.non_execution_cus;
    expected_data_bytes  += txns[i].payload_sz;
  }
  FD_TEST( rebate->total_cost_rebate    ==expected_rebated_cus );
  FD_TEST( rebate->data_bytes_rebate    ==expected_data_bytes  );
  FD_TEST( rebate->microblock_cnt_rebate==3UL                 );
  FD_TEST( rebate->alloc_rebate         ==0UL                 );
  FD_TEST( rebate->ib_result            ==0                   );

  FD_TEST( test_read_lamports( env, &fee_payer  )==payer_start      );
  FD_TEST( test_read_lamports( env, &recipient0 )==recipient0_start );
  FD_TEST( test_read_lamports( env, &recipient1 )==recipient1_start );
  FD_TEST( test_read_lamports( env, &recipient2 )==recipient2_start );

  FD_TEST( env->execle->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_UNLANDED_IDX ]==3UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_INSTRUCTION_ERROR_IDX ]==1UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_BUNDLE_PEER_IDX ]==2UL );

  test_env_destroy( env );
}

FD_UNIT_TEST( execle_bundle_progcache ) {
  /* Close a deployed/rooted program in the first transaction,
     then try to invoke it in the second transaction (should fail). */
  test_env_t * env = test_env_create();
  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );

  fd_pubkey_t authority   = { .ul = { 0xaaa0UL } };
  fd_pubkey_t recipient   = { .ul = { 0xaaa1UL } };
  fd_pubkey_t program     = { .ul = { 0xaaa3UL } };
  fd_pubkey_t programdata = { .ul = { 0xaaa4UL } };

  ulong const authority_start   = 1000000000UL;
  ulong const recipient_start   = 123UL;
  ulong const program_lamports  = 1000000UL;
  ulong const programdata_lamports = 2000000UL;

  test_fund_account( env, &authority,  authority_start  );
  test_fund_account( env, &recipient,  recipient_start  );

  uchar program_state_data[ SIZE_OF_PROGRAM ];
  fd_bpf_state_t program_state = {
    .discriminant = FD_BPF_STATE_PROGRAM,
    .inner.program.programdata_address = programdata
  };
  ulong out_sz = 0UL;
  FD_TEST( !fd_bpf_state_encode( &program_state, program_state_data, sizeof(program_state_data), &out_sz ) );

  uchar programdata_state_data[ PROGRAMDATA_METADATA_SIZE + test_bpf_program_sz ];
  fd_bpf_state_t programdata_state = {
    .discriminant = FD_BPF_STATE_PROGRAM_DATA,
    .inner.program_data = {
      .slot = bank->f.slot - 1UL,
      .upgrade_authority_address = authority,
      .has_upgrade_authority_address = 1
    }
  };
  out_sz = 0UL;
  FD_TEST( !fd_bpf_state_encode( &programdata_state, programdata_state_data, PROGRAMDATA_METADATA_SIZE, &out_sz ) );
  fd_memcpy( programdata_state_data + PROGRAMDATA_METADATA_SIZE, test_bpf_program, test_bpf_program_sz );

  test_put_account_rooted( env, &program, &fd_solana_bpf_loader_upgradeable_program_id,
                           program_lamports, bank->f.slot-1UL, 1, program_state_data, sizeof(program_state_data) );
  test_put_account_rooted( env, &programdata, &fd_solana_bpf_loader_upgradeable_program_id,
                           programdata_lamports, bank->f.slot-1UL, 0,
                           programdata_state_data, sizeof(programdata_state_data) );

  fd_txn_p_t txns[2];
  test_build_bpf_close_txn( &txns[0], bank, authority, recipient, program, programdata );
  test_build_program_invoke_txn( &txns[1], bank, authority, program );
  test_execle_run( env, txns, 2UL, 16U, 41UL, 1 );

  test_assert_bundle_out( env, 2UL, 16U );
  FD_TEST( env->execle->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( env->execle->txn_out[1].err.txn_err==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR );
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_txn_p_t const * out_txn = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( i )->chunk );
    FD_TEST( !env->execle->txn_out[i].err.is_committable );
    FD_TEST( !(out_txn->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS) );
    FD_TEST( !(out_txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) );

    FD_TEST( out_txn->execle_cu.actual_consumed_cus==0U );
    FD_TEST( out_txn->execle_cu.rebated_cus==
             txns[i].pack_cu.requested_exec_plus_acct_data_cus + txns[i].pack_cu.non_execution_cus );

    fd_microblock_trailer_t const * trailer = test_out_poh_trailer_bundle( env, i );
    FD_TEST( trailer->pack_txn_idx==41UL+i );
    FD_TEST( trailer->tips==0UL );
    /* hash not checked: empty bmtree (no EXECUTE_SUCCESS txns) */
    test_assert_txn_ns_dt_ordered( &trailer->txn_ns_dt );
  }
  FD_TEST( test_read_lamports( env, &authority   )==authority_start   );
  FD_TEST( test_read_lamports( env, &recipient   )==recipient_start   );
  FD_TEST( test_read_lamports( env, &program     )==program_lamports  );
  FD_TEST( test_read_lamports( env, &programdata )==programdata_lamports );

  FD_TEST( env->execle->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_UNLANDED_IDX ]==2UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_INSTRUCTION_ERROR_IDX ]==1UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_BUNDLE_PEER_IDX ]==1UL );

  test_env_destroy( env );
}

FD_UNIT_TEST( execle_bundle_nonce_dup ) {
  /* Advance the same durable nonce twice */
  test_env_t * env = test_env_create();

  fd_pubkey_t fee_payer  = { .ul = { 0xccc0UL } };
  fd_pubkey_t nonce_key  = { .ul = { 0xccc1UL } };
  fd_pubkey_t recipient0 = { .ul = { 0xccc2UL } };
  fd_pubkey_t recipient1 = { .ul = { 0xccc3UL } };

  ulong const fee_payer_start  = 10000000000UL;
  ulong const nonce_start      = 10000000000UL;
  ulong const recipient0_start = 1000000000UL;
  ulong const recipient1_start = 1000000000UL;
  ulong const transfer0        = 12345UL;
  ulong const transfer1        = 67890UL;
  ulong const fee              = 5000UL;

  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );
  fd_blockhash_info_t * blockhash_info = (fd_blockhash_info_t *)fd_blockhashes_peek_last( &bank->f.block_hash_queue );
  FD_TEST( blockhash_info );
  blockhash_info->lamports_per_signature = fee;

  fd_hash_t stale_blockhash = {0};
  fd_memset( stale_blockhash.uc, 0x42, sizeof(fd_hash_t) );
  fd_hash_t durable_nonce;
  test_durable_nonce_from_blockhash( &durable_nonce, &stale_blockhash );

  test_fund_account( env, &fee_payer,  fee_payer_start  );
  test_fund_account( env, &recipient0, recipient0_start );
  test_fund_account( env, &recipient1, recipient1_start );
  test_put_nonce_account_rooted( env, &nonce_key, &fee_payer, &durable_nonce, nonce_start );

  fd_txn_p_t txns[2];
  test_build_durable_nonce_transfer_txn( &txns[0], fee_payer, nonce_key, recipient0, &durable_nonce, transfer0, 51UL );
  test_build_durable_nonce_transfer_txn( &txns[1], fee_payer, nonce_key, recipient1, &durable_nonce, transfer1, 52UL );
  test_execle_run( env, txns, 2UL, 20U, 51UL, 1 );

  test_assert_bundle_out( env, 2UL, 20U );
  FD_TEST( env->execle->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( env->execle->txn_out[1].err.txn_err==FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_WRONG_NONCE );

  fd_txn_p_t const * out_txn0 = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( 0UL )->chunk );
  fd_txn_p_t const * out_txn1 = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( 1UL )->chunk );
  FD_TEST( !env->execle->txn_out[0].err.is_committable );
  FD_TEST( !env->execle->txn_out[1].err.is_committable );
  FD_TEST( !(out_txn0->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS) );
  FD_TEST( !(out_txn0->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) );
  FD_TEST( !(out_txn1->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS) );
  FD_TEST( !(out_txn1->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) );
  FD_TEST( out_txn0->flags & FD_TXN_P_FLAGS_DURABLE_NONCE );
  FD_TEST( out_txn1->flags & FD_TXN_P_FLAGS_DURABLE_NONCE );
  FD_TEST( (out_txn0->flags & FD_TXN_P_FLAGS_RESULT_MASK)==((uint)(-FD_RUNTIME_TXN_ERR_BUNDLE_PEER)<<24) );
  FD_TEST( (out_txn1->flags & FD_TXN_P_FLAGS_RESULT_MASK)==((uint)(-FD_RUNTIME_TXN_ERR_BLOCKHASH_FAIL_WRONG_NONCE)<<24) );

  for( ulong i=0UL; i<2UL; i++ ) {
    fd_txn_p_t const * out_txn = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( i )->chunk );
    FD_TEST( out_txn->execle_cu.actual_consumed_cus==0U );
    FD_TEST( out_txn->execle_cu.rebated_cus==
             txns[i].pack_cu.requested_exec_plus_acct_data_cus + txns[i].pack_cu.non_execution_cus );

    fd_microblock_trailer_t const * trailer = test_out_poh_trailer_bundle( env, i );
    FD_TEST( trailer->pack_txn_idx==51UL+i );
    FD_TEST( trailer->tips==0UL );
    /* hash not checked: empty bmtree (no EXECUTE_SUCCESS txns) */
    test_assert_txn_ns_dt_ordered( &trailer->txn_ns_dt );
  }

  FD_TEST( test_read_lamports( env, &fee_payer  )==fee_payer_start  );
  FD_TEST( test_read_lamports( env, &nonce_key  )==nonce_start      );
  FD_TEST( test_read_lamports( env, &recipient0 )==recipient0_start );
  FD_TEST( test_read_lamports( env, &recipient1 )==recipient1_start );

  FD_TEST( env->execle->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_UNLANDED_IDX ]==2UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_NONCE_WRONG_BLOCKHASH_IDX ]==1UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_BUNDLE_PEER_IDX ]==1UL );

  test_env_destroy( env );
}

FD_UNIT_TEST( execle_bundle_nonce_dup2 ) {
  /* Advance the same nonce account twice with valid durable nonces */
  test_env_t * env = test_env_create();

  fd_pubkey_t fee_payer  = { .ul = { 0xcce0UL } };
  fd_pubkey_t nonce_key  = { .ul = { 0xcce1UL } };
  fd_pubkey_t recipient0 = { .ul = { 0xcce2UL } };
  fd_pubkey_t recipient1 = { .ul = { 0xcce3UL } };

  ulong const fee_payer_start  = 10000000000UL;
  ulong const nonce_start      = 10000000000UL;
  ulong const recipient0_start = 1000000000UL;
  ulong const recipient1_start = 1000000000UL;
  ulong const transfer0        = 12345UL;
  ulong const transfer1        = 67890UL;
  ulong const fee              = 5000UL;

  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );
  fd_blockhash_info_t * blockhash_info = (fd_blockhash_info_t *)fd_blockhashes_peek_last( &bank->f.block_hash_queue );
  FD_TEST( blockhash_info );
  blockhash_info->lamports_per_signature = fee;

  fd_hash_t stale_blockhash = {0};
  fd_memset( stale_blockhash.uc, 0x43, sizeof(fd_hash_t) );
  fd_hash_t durable_nonce0;
  test_durable_nonce_from_blockhash( &durable_nonce0, &stale_blockhash );

  fd_hash_t const * last_blockhash = fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue );
  FD_TEST( last_blockhash );
  fd_hash_t durable_nonce1;
  test_durable_nonce_from_blockhash( &durable_nonce1, last_blockhash );

  test_fund_account( env, &fee_payer,  fee_payer_start  );
  test_fund_account( env, &recipient0, recipient0_start );
  test_fund_account( env, &recipient1, recipient1_start );
  test_put_nonce_account_rooted( env, &nonce_key, &fee_payer, &durable_nonce0, nonce_start );

  fd_txn_p_t txns[2];
  test_build_durable_nonce_transfer_txn( &txns[0], fee_payer, nonce_key, recipient0, &durable_nonce0, transfer0, 53UL );
  test_build_durable_nonce_transfer_txn( &txns[1], fee_payer, nonce_key, recipient1, &durable_nonce1, transfer1, 54UL );
  test_execle_run( env, txns, 2UL, 22U, 53UL, 1 );

  test_assert_bundle_out( env, 2UL, 22U );
  FD_TEST( env->execle->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( env->execle->txn_out[1].err.txn_err==FD_RUNTIME_TXN_ERR_BLOCKHASH_NONCE_ALREADY_ADVANCED );

  fd_txn_p_t const * out_txn0 = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( 0UL )->chunk );
  fd_txn_p_t const * out_txn1 = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( 1UL )->chunk );
  FD_TEST( !env->execle->txn_out[0].err.is_committable );
  FD_TEST( !env->execle->txn_out[1].err.is_committable );
  FD_TEST( !(out_txn0->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS) );
  FD_TEST( !(out_txn0->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) );
  FD_TEST( !(out_txn1->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS) );
  FD_TEST( !(out_txn1->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) );
  FD_TEST( out_txn0->flags & FD_TXN_P_FLAGS_DURABLE_NONCE );
  FD_TEST( out_txn1->flags & FD_TXN_P_FLAGS_DURABLE_NONCE );
  FD_TEST( (out_txn0->flags & FD_TXN_P_FLAGS_RESULT_MASK)==((uint)(-FD_RUNTIME_TXN_ERR_BUNDLE_PEER)<<24) );
  FD_TEST( (out_txn1->flags & FD_TXN_P_FLAGS_RESULT_MASK)==((uint)(-FD_RUNTIME_TXN_ERR_BLOCKHASH_NONCE_ALREADY_ADVANCED)<<24) );

  for( ulong i=0UL; i<2UL; i++ ) {
    fd_txn_p_t const * out_txn = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( i )->chunk );
    FD_TEST( out_txn->execle_cu.actual_consumed_cus==0U );
    FD_TEST( out_txn->execle_cu.rebated_cus==
             txns[i].pack_cu.requested_exec_plus_acct_data_cus + txns[i].pack_cu.non_execution_cus );

    fd_microblock_trailer_t const * trailer = test_out_poh_trailer_bundle( env, i );
    FD_TEST( trailer->pack_txn_idx==53UL+i );
    FD_TEST( trailer->tips==0UL );
    /* hash not checked: empty bmtree (no EXECUTE_SUCCESS txns) */
    test_assert_txn_ns_dt_ordered( &trailer->txn_ns_dt );
  }

  FD_TEST( test_read_lamports( env, &fee_payer  )==fee_payer_start  );
  FD_TEST( test_read_lamports( env, &nonce_key  )==nonce_start      );
  FD_TEST( test_read_lamports( env, &recipient0 )==recipient0_start );
  FD_TEST( test_read_lamports( env, &recipient1 )==recipient1_start );

  FD_TEST( env->execle->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_UNLANDED_IDX ]==2UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_NONCE_ALREADY_ADVANCED_IDX ]==1UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_BUNDLE_PEER_IDX ]==1UL );

  test_env_destroy( env );
}

FD_UNIT_TEST( execle_bundle_dup ) {
  /* Duplicate transaction in a bundle causing a status cache collision */
  test_env_t * env = test_env_create();
  fd_bank_t * bank = fd_svm_mini_bank( env->mini, env->bank_idx );

  fd_pubkey_t fee_payer = { .ul = { 0xeeeeUL } };
  fd_pubkey_t shared    = { .ul = { 0xffffUL } };
  test_fund_account( env, &fee_payer, 1000000000UL );

  fd_txn_p_t txns[2];
  test_build_empty_txn( &txns[0], bank, fee_payer, shared, 61UL, 0 );
  txns[1] = txns[0];
  test_execle_run( env, txns, 2UL, 24U, 61UL, 1 );

  test_assert_bundle_out( env, 2UL, 24U );
  FD_TEST( !env->execle->txn_out[0].err.is_committable );
  FD_TEST( !env->execle->txn_out[1].err.is_committable );
  FD_TEST( env->execle->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( env->execle->txn_out[1].err.txn_err==FD_RUNTIME_TXN_ERR_ALREADY_PROCESSED );

  fd_txn_p_t const * out_txn0 = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( 0UL )->chunk );
  fd_txn_p_t const * out_txn1 = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( 1UL )->chunk );
  FD_TEST( !(out_txn0->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS) );
  FD_TEST( !(out_txn0->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) );
  FD_TEST( !(out_txn1->flags & FD_TXN_P_FLAGS_SANITIZE_SUCCESS) );
  FD_TEST( !(out_txn1->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) );
  FD_TEST( (out_txn0->flags & FD_TXN_P_FLAGS_RESULT_MASK)==((uint)(-FD_RUNTIME_TXN_ERR_BUNDLE_PEER)<<24) );
  FD_TEST( (out_txn1->flags & FD_TXN_P_FLAGS_RESULT_MASK)==((uint)(-FD_RUNTIME_TXN_ERR_ALREADY_PROCESSED)<<24) );

  for( ulong i=0UL; i<2UL; i++ ) {
    fd_txn_p_t const * out_txn = fd_chunk_to_laddr( env->execle->out_poh->mem, test_out_poh_meta( i )->chunk );
    FD_TEST( out_txn->execle_cu.actual_consumed_cus==0U );
    FD_TEST( out_txn->execle_cu.rebated_cus==
             txns[i].pack_cu.requested_exec_plus_acct_data_cus + txns[i].pack_cu.non_execution_cus );

    fd_microblock_trailer_t const * trailer = test_out_poh_trailer_bundle( env, i );
    FD_TEST( trailer->pack_txn_idx==61UL+i );
    FD_TEST( trailer->tips==0UL );
    /* hash not checked: empty bmtree (no EXECUTE_SUCCESS txns) */
    test_assert_txn_ns_dt_ordered( &trailer->txn_ns_dt );
  }

  FD_TEST( env->execle->metrics.txn_landed[ FD_METRICS_ENUM_TRANSACTION_LANDED_V_UNLANDED_IDX ]==2UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_ALREADY_PROCESSED_IDX ]==1UL );
  FD_TEST( env->execle->metrics.txn_result[ FD_METRICS_ENUM_TRANSACTION_RESULT_V_BUNDLE_PEER_IDX ]==1UL );

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
  limits->wksp_addl_sz            = 5UL<<30;
  limits->accdb_joiner_cnt        = 2UL; /* mini's runtime join + the exec tile join */

  mini = fd_svm_test_boot( &argc, &argv, limits );
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL ) );

  fd_unit_tests( argc, argv );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
