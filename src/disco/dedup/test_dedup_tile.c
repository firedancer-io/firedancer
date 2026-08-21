#define FD_TILE_TEST
#include "fd_dedup_tile.c"
#include "../topo/fd_topob.h"
#include <stdlib.h>
#include <unistd.h>

#define IN_IDX_GOSSIP   (0UL)
#define IN_IDX_VERIFY   (1UL)
#define IN_IDX_EXECUTED (2UL)
#define IN_IDX_REPLAY   (3UL)

static void
test_seccomp( void ) {
  int   out_fds[2];
  ulong nfds = populate_allowed_fds( NULL, NULL, 2UL, out_fds );
  FD_TEST( nfds>=1 && nfds<=2 );
  FD_TEST( out_fds[0]==STDERR_FILENO );

  struct sock_filter filter[ 32 ];
  populate_allowed_seccomp( NULL, NULL, 32UL, filter );
}

struct test_env {
  fd_topo_t *      topo;
  fd_dedup_ctx_t * ctx;
  void *           scratch_mem;

  fd_frag_meta_t *   out_mcache[1];
  fd_stem_context_t  stem[1];
  ulong              stem_seqs[1];
  ulong              stem_depths[1];
  ulong              stem_cr_avail[1];
  ulong              stem_min_cr_avail[1];
  int                out_reliable[1];
  fd_txn_m_t const * last_out_txnm;

  void * link_mcache_mem[5];
  void * link_dcache_mem[5];
  ulong  link_mem_cnt;
};

typedef struct test_env test_env_t;

static fd_topo_link_t *
mock_link_create( test_env_t * env,
                  char const * name,
                  ulong        mtu ) {
  ulong const depth = 16UL;
  fd_topo_link_t * link = fd_topob_link( env->topo, name, "wksp", depth, mtu, 0UL );
  ulong data_sz = fd_dcache_req_data_sz( mtu, depth, 1UL, 1 );

  FD_TEST( env->link_mem_cnt<5UL );
  void * mcache_mem;
  void * dcache_mem;
  FD_TEST( !posix_memalign( &mcache_mem, fd_mcache_align(), fd_mcache_footprint( depth, 0UL ) ) );
  FD_TEST( !posix_memalign( &dcache_mem, fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ) ) );

  link->mcache = fd_mcache_join( fd_mcache_new( mcache_mem, depth, 0UL, 0UL ) );
  link->dcache = fd_dcache_join( fd_dcache_new( dcache_mem, data_sz, 0UL ) );
  FD_TEST( link->mcache );
  FD_TEST( link->dcache );

  env->topo->objs[ link->mcache_obj_id ].offset = (ulong)mcache_mem;
  env->topo->objs[ link->dcache_obj_id ].offset = (ulong)dcache_mem;

  env->link_mcache_mem[ env->link_mem_cnt ] = mcache_mem;
  env->link_dcache_mem[ env->link_mem_cnt ] = dcache_mem;
  env->link_mem_cnt++;

  return link;
}

static void
test_env_create( test_env_t * env,
                 ulong        tcache_depth ) {
  fd_memset( env, 0, sizeof(test_env_t) );

  void * topo_mem;
  FD_TEST( !posix_memalign( &topo_mem, alignof(fd_topo_t), sizeof(fd_topo_t) ) );
  env->topo = fd_topob_new( topo_mem, "dedup-test" );
  FD_TEST( env->topo );

  fd_topo_wksp_t * wksp = fd_topob_wksp( env->topo, "wksp" );
  wksp->wksp = NULL;

  fd_topo_tile_t * tile = fd_topob_tile( env->topo, "dedup", "wksp", "wksp", 0UL, 0, 0, 0 );
  tile->dedup.tcache_depth = tcache_depth;

  ulong ctx_align = fd_ulong_max( scratch_align(), fd_tcache_align() );
  FD_TEST( !posix_memalign( &env->scratch_mem, ctx_align, scratch_footprint( tile ) ) );
  env->topo->objs[ tile->tile_obj_id ].offset = (ulong)env->scratch_mem;

  mock_link_create( env, "gossip_dedup", FD_TPU_RAW_MTU );
  mock_link_create( env, "verify_dedup", FD_TPU_PARSED_MTU );
  mock_link_create( env, "executed_txn", FD_TXN_SIGNATURE_SZ );
  mock_link_create( env, "replay_out",   sizeof(fd_replay_message_t) );
  fd_topo_link_t * out_link = mock_link_create( env, "dedup_out", FD_TPU_PARSED_MTU );

  fd_topob_tile_in ( env->topo, "dedup", 0UL, "wksp", "gossip_dedup", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in ( env->topo, "dedup", 0UL, "wksp", "verify_dedup", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in ( env->topo, "dedup", 0UL, "wksp", "executed_txn", 0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_in ( env->topo, "dedup", 0UL, "wksp", "replay_out",   0UL, FD_TOPOB_UNRELIABLE, FD_TOPOB_POLLED );
  fd_topob_tile_out( env->topo, "dedup", 0UL,         "dedup_out",    0UL );

  privileged_init  ( env->topo, tile );
  unprivileged_init( env->topo, tile );

  env->ctx = fd_topo_obj_laddr( env->topo, tile->tile_obj_id );

  env->out_mcache[0]        = out_link->mcache;
  env->stem_seqs[0]         = 0UL;
  env->stem_depths[0]       = fd_mcache_depth( out_link->mcache );
  env->stem_cr_avail[0]     = ULONG_MAX;
  env->stem_min_cr_avail[0] = 0UL;
  env->out_reliable[0]      = 1;

  *env->stem = (fd_stem_context_t){
    .mcaches             = env->out_mcache,
    .seqs                = env->stem_seqs,
    .depths              = env->stem_depths,
    .cr_avail            = env->stem_cr_avail,
    .min_cr_avail        = env->stem_min_cr_avail,
    .cr_decrement_amount = 0UL,
    .out_reliable        = env->out_reliable,
  };
}

static void
test_env_destroy( test_env_t * env ) {
  for( ulong i=0UL; i<env->link_mem_cnt; i++ ) {
    free( env->link_dcache_mem[i] );
    free( env->link_mcache_mem[i] );
  }

  free( env->scratch_mem );
  free( env->topo );
}

static fd_frag_meta_t const *
published_meta( test_env_t * env,
                ulong        seq ) {
  return env->out_mcache[0] + fd_mcache_line_idx( seq, env->stem_depths[0] );
}

static fd_txn_m_t const *
published_txnm( test_env_t * env ) {
  return env->last_out_txnm;
}

static void
inject( test_env_t * env,
        ulong        in_idx,
        ulong        sig,
        void const * src,
        ulong        sz ) {
  fd_dedup_ctx_t * ctx   = env->ctx;
  ulong            chunk = ctx->in[ in_idx ].chunk0;
  fd_memcpy( fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), src, sz );
  during_frag( ctx, in_idx, 0UL, sig, chunk, sz, 0UL );
  env->last_out_txnm = fd_chunk_to_laddr_const( ctx->out_mem, ctx->out_chunk );
  after_frag ( ctx, in_idx, 0UL, sig, sz, 0UL, 0UL, env->stem );
}

static ulong
build_min_txn( uchar *       out,
               uchar const   sig[ 64 ] ) {
  uchar * cur = out;
  *cur++ = 1;                                   /* signature_cnt */
  fd_memcpy( cur, sig, FD_TXN_SIGNATURE_SZ ); cur += FD_TXN_SIGNATURE_SZ;
  *cur++ = 1;                                   /* header_b0 == signature_cnt (legacy) */
  *cur++ = 0;                                   /* readonly_signed_cnt */
  *cur++ = 0;                                   /* readonly_unsigned_cnt */
  *cur++ = 1;                                   /* acct_addr_cnt (compact-u16) */
  fd_memset( cur, 0x11, 32UL ); cur += 32UL;    /* fee payer / signer account */
  fd_memset( cur, 0x22, 32UL ); cur += 32UL;    /* recent blockhash */
  *cur++ = 0;                                   /* instr_cnt */
  return (ulong)( cur-out );
}

static void
fill_txnm_unparsed( fd_txn_m_t * txnm,
                    uchar const  sig[ 64 ],
                    ulong        bundle_id ) {
  fd_memset( txnm, 0, sizeof(fd_txn_m_t) );
  txnm->payload_sz            = (ushort)build_min_txn( fd_txn_m_payload( txnm ), sig );
  txnm->block_engine.bundle_id = bundle_id;
}

static void
fill_txnm_parsed( fd_txn_m_t * txnm,
                  uchar const  sig[ 64 ],
                  ulong        bundle_id ) {
  fill_txnm_unparsed( txnm, sig, bundle_id );
  txnm->txn_t_sz = (ushort)fd_txn_parse( fd_txn_m_payload( txnm ), txnm->payload_sz, fd_txn_m_txn_t( txnm ), NULL );
  FD_TEST( txnm->txn_t_sz );
}

static void
send_verify_txn( test_env_t * env,
                 uchar const  sig[ 64 ],
                 ulong        bundle_id ) {
  uchar buf[ FD_TPU_PARSED_MTU ] __attribute__((aligned(alignof(fd_txn_m_t))));
  fd_txn_m_t * txnm = (fd_txn_m_t *)buf;
  fill_txnm_parsed( txnm, sig, bundle_id );
  inject( env, IN_IDX_VERIFY, 0UL, txnm, fd_txn_m_realized_footprint( txnm, 1, 0 ) );
}

static void
send_gossip_txn( test_env_t * env,
                 uchar const  sig[ 64 ] ) {
  uchar buf[ FD_TPU_PARSED_MTU ] __attribute__((aligned(alignof(fd_txn_m_t))));
  fd_txn_m_t * txnm = (fd_txn_m_t *)buf;
  fill_txnm_unparsed( txnm, sig, 0UL );
  inject( env, IN_IDX_GOSSIP, 0UL, txnm, fd_txn_m_realized_footprint( txnm, 0, 0 ) );
}

static void
send_executed_sig( test_env_t * env,
                   uchar const  sig[ 64 ] ) {
  inject( env, IN_IDX_EXECUTED, 0UL, sig, FD_TXN_SIGNATURE_SZ );
}

static void
send_replay_executed( test_env_t * env,
                      uchar const  sig[ 64 ],
                      int          is_committable ) {
  fd_replay_txn_executed_t exec;
  fd_memset( &exec, 0, sizeof(exec) );
  exec.txn->payload_sz = build_min_txn( exec.txn->payload, sig );
  FD_TEST( fd_txn_parse( exec.txn->payload, exec.txn->payload_sz, TXN( exec.txn ), NULL ) );
  exec.is_committable = is_committable;
  inject( env, IN_IDX_REPLAY, REPLAY_SIG_TXN_EXECUTED, &exec, sizeof(exec) );
}

static void
send_replay_other( test_env_t * env ) {
  fd_replay_message_t msg;
  fd_memset( &msg, 0, sizeof(msg) );
  inject( env, IN_IDX_REPLAY, REPLAY_SIG_RESET, &msg, sizeof(msg) );
}

static void
sig_fill( uchar out[ 64 ],
         uchar tag ) {
  fd_memset( out, tag, 64UL );
}

static void
test_fresh_and_duplicate( void ) {
  test_env_t env[1];
  test_env_create( env, 128UL );

  uchar sig_a[ 64 ]; sig_fill( sig_a, 0xA1 );
  uchar sig_b[ 64 ]; sig_fill( sig_b, 0xB2 );

  send_verify_txn( env, sig_a, 0UL );
  FD_TEST( env->stem_seqs[0]==1UL );
  FD_TEST( published_meta( env, 0UL )->sig==0UL );
  FD_TEST( published_txnm( env )->payload_sz>0 );
  FD_TEST( env->ctx->metrics.dedup_tile_result[ FD_METRICS_ENUM_DEDUP_TILE_RESULT_V_SUCCESS_IDX ]==1UL );

  send_verify_txn( env, sig_a, 0UL );
  FD_TEST( env->stem_seqs[0]==1UL );
  FD_TEST( env->ctx->metrics.dedup_tile_result[ FD_METRICS_ENUM_DEDUP_TILE_RESULT_V_DEDUP_FAILURE_IDX ]==1UL );

  send_verify_txn( env, sig_b, 0UL );
  FD_TEST( env->stem_seqs[0]==2UL );
  FD_TEST( env->ctx->metrics.dedup_tile_result[ FD_METRICS_ENUM_DEDUP_TILE_RESULT_V_SUCCESS_IDX ]==2UL );

  test_env_destroy( env );
}

static void
test_tcache_eviction( void ) {
  test_env_t env[1];
  test_env_create( env, 4UL );

  uchar sig[5][64];
  for( ulong i=0UL; i<5UL; i++ ) sig_fill( sig[i], (uchar)(0x10U+i) );

  for( ulong i=0UL; i<4UL; i++ ) {
    send_verify_txn( env, sig[i], 0UL );
    FD_TEST( env->stem_seqs[0]==i+1UL );
  }

  send_verify_txn( env, sig[4], 0UL );
  FD_TEST( env->stem_seqs[0]==5UL );

  send_verify_txn( env, sig[4], 0UL );
  FD_TEST( env->stem_seqs[0]==5UL );
  send_verify_txn( env, sig[1], 0UL );
  FD_TEST( env->stem_seqs[0]==5UL );

  send_verify_txn( env, sig[0], 0UL );
  FD_TEST( env->stem_seqs[0]==6UL );

  test_env_destroy( env );
}

static void
test_gossip_parse_and_dedup( void ) {
  test_env_t env[1];
  test_env_create( env, 128UL );

  uchar sig[ 64 ]; sig_fill( sig, 0xC3 );
  ulong gossip_rx0 = FD_MCNT_GET( DEDUP, VOTE_GOSSIP_RX );

  send_gossip_txn( env, sig );
  FD_TEST( env->stem_seqs[0]==1UL );
  FD_TEST( published_txnm( env )->txn_t_sz>0 );
  FD_TEST( FD_MCNT_GET( DEDUP, VOTE_GOSSIP_RX )==gossip_rx0+1UL );

  send_gossip_txn( env, sig );
  FD_TEST( env->stem_seqs[0]==1UL );
  FD_TEST( FD_MCNT_GET( DEDUP, VOTE_GOSSIP_RX )==gossip_rx0+2UL );

  test_env_destroy( env );
}

static void
test_executed_txn_poisons_cache( void ) {
  test_env_t env[1];
  test_env_create( env, 128UL );

  uchar sig_x[ 64 ]; sig_fill( sig_x, 0xD4 );
  uchar sig_y[ 64 ]; sig_fill( sig_y, 0xE5 );

  send_executed_sig( env, sig_x );
  FD_TEST( env->stem_seqs[0]==0UL );

  send_verify_txn( env, sig_x, 0UL );
  FD_TEST( env->stem_seqs[0]==0UL );

  send_verify_txn( env, sig_y, 0UL );
  FD_TEST( env->stem_seqs[0]==1UL );

  test_env_destroy( env );
}

static void
test_replay_executed_poisons_cache( void ) {
  test_env_t env[1];
  test_env_create( env, 128UL );

  uchar sig_committed[ 64 ]; sig_fill( sig_committed, 0xF6 );
  uchar sig_uncommitted[ 64 ]; sig_fill( sig_uncommitted, 0x07 );
  uchar sig_ignored[ 64 ]; sig_fill( sig_ignored, 0x08 );

  send_replay_executed( env, sig_committed, 1 );
  FD_TEST( env->stem_seqs[0]==0UL );
  send_verify_txn( env, sig_committed, 0UL );
  FD_TEST( env->stem_seqs[0]==0UL );

  send_replay_executed( env, sig_uncommitted, 0 );
  send_verify_txn( env, sig_uncommitted, 0UL );
  FD_TEST( env->stem_seqs[0]==1UL );

  send_replay_other( env );
  send_verify_txn( env, sig_ignored, 0UL );
  FD_TEST( env->stem_seqs[0]==2UL );

  test_env_destroy( env );
}

static void
test_bundle_dedup( void ) {
  test_env_t env[1];
  test_env_create( env, 128UL );

  uchar sig_a[ 64 ]; sig_fill( sig_a, 0x21 );
  uchar sig_b[ 64 ]; sig_fill( sig_b, 0x22 );
  uchar sig_c[ 64 ]; sig_fill( sig_c, 0x23 );

  send_verify_txn( env, sig_a, 100UL );
  FD_TEST( env->stem_seqs[0]==1UL );
  FD_TEST( published_meta( env, 0UL )->sig==1UL );

  send_verify_txn( env, sig_a, 100UL );
  FD_TEST( env->stem_seqs[0]==1UL );
  FD_TEST( env->ctx->metrics.dedup_tile_result[ FD_METRICS_ENUM_DEDUP_TILE_RESULT_V_DEDUP_FAILURE_IDX ]==1UL );

  send_verify_txn( env, sig_b, 100UL );
  FD_TEST( env->stem_seqs[0]==1UL );
  FD_TEST( env->ctx->metrics.dedup_tile_result[ FD_METRICS_ENUM_DEDUP_TILE_RESULT_V_BUNDLE_PEER_FAILURE_IDX ]==1UL );

  send_verify_txn( env, sig_c, 200UL );
  FD_TEST( env->stem_seqs[0]==2UL );
  FD_TEST( published_meta( env, 1UL )->sig==1UL );

  test_env_destroy( env );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static uchar metrics_scratch[ FD_METRICS_FOOTPRINT( 0UL ) ] __attribute__((aligned(FD_METRICS_ALIGN)));
  fd_metrics_register( (ulong *)fd_metrics_new( metrics_scratch, 0UL ) );

  FD_TEST( scratch_align()==alignof(fd_dedup_ctx_t) );

  test_seccomp();
  test_fresh_and_duplicate();
  test_tcache_eviction();
  test_gossip_parse_and_dedup();
  test_executed_txn_poisons_cache();
  test_replay_executed_poisons_cache();
  test_bundle_dedup();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
