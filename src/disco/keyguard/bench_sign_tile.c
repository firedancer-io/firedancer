/* Benchmarks sign tile signing throughput using two threads:
   tile 1 runs stem_run1 (the sign tile run loop), tile 0 sends
   pipelined signing requests and measures throughput. */

#define _GNU_SOURCE
#include "../fd_disco.h"
#include "fd_keyguard.h"
#include "fd_keyload.h"

#include <stdio.h>
#include <stdlib.h> /* mktemp */
#include <unistd.h>

#if FD_HAS_HOSTED && FD_HAS_ALLOCA

static volatile int stop;

#define STEM_CALLBACK_SHOULD_SHUTDOWN(ctx) FD_VOLATILE_CONST(stop)
#define FD_TILE_TEST
#include "fd_sign_tile.c"

typedef struct {
  fd_frag_meta_t * req_mcache;
  uchar *          req_dcache;
  ulong *          req_fseq;

  fd_frag_meta_t * resp_mcache;
  uchar *          resp_dcache;
  ulong *          resp_fseq;

  fd_keyswitch_t * keyswitch;

  char const *     key_path;

  ulong *          metrics;
  fd_wksp_t *      wksp;
} bench_sign_cfg_t;

static int
sign_tile_main( int     argc,
                char ** argv ) {
  (void)argc;
  bench_sign_cfg_t * cfg = (bench_sign_cfg_t *)fd_type_pun( argv );

  fd_metrics_register( cfg->metrics );

  fd_sign_ctx_t ctx[1];
  memset( ctx, 0, sizeof(fd_sign_ctx_t) );

  uchar * identity_key = fd_keyload_load( cfg->key_path, 0 );
  ctx->private_key = identity_key;
  ctx->public_key  = identity_key + 32UL;

  FD_TEST( fd_sha512_join( fd_sha512_new( ctx->sha512 ) ) );
  fd_histf_join( fd_histf_new( ctx->sign_duration,
                               FD_MHIST_SECONDS_MIN( SIGN, SIGN_DURATION_SECONDS ),
                               FD_MHIST_SECONDS_MAX( SIGN, SIGN_DURATION_SECONDS ) ) );

  ctx->keyswitch    = cfg->keyswitch;
  ctx->av_keyswitch = NULL;

  ctx->authorized_voters_cnt = 0UL;

  derive_fields( ctx );

  ctx->in[0].role   = FD_KEYGUARD_ROLE_LEADER;
  ctx->in[0].mem    = cfg->wksp;
  ctx->in[0].chunk0 = fd_dcache_compact_chunk0( cfg->wksp, cfg->req_dcache );
  ctx->in[0].wmark  = fd_dcache_compact_wmark ( cfg->wksp, cfg->req_dcache, 32UL );
  ctx->in[0].mtu    = 32UL;
  for( ulong i=1UL; i<MAX_IN; i++ ) ctx->in[i].role = -1;

  ctx->out[0].out_mem    = cfg->wksp;
  ctx->out[0].out_chunk0 = fd_dcache_compact_chunk0( cfg->wksp, cfg->resp_dcache );
  ctx->out[0].out_wmark  = fd_dcache_compact_wmark ( cfg->wksp, cfg->resp_dcache, 64UL );
  ctx->out[0].out_chunk  = ctx->out[0].out_chunk0;

  fd_frag_meta_t const * in_mcache[1]  = { cfg->req_mcache  };
  ulong *                in_fseq[1]    = { cfg->req_fseq    };
  fd_frag_meta_t *       out_mcache[1] = { cfg->resp_mcache };

  ulong            cons_out[1]  = { 0UL           };
  ulong *          cons_fseq[1] = { cfg->resp_fseq };
  volatile ulong   cons_slow_val = 0;
  volatile ulong * cons_slow[1] = { &cons_slow_val };

  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, (uint)fd_tickcount(), 0UL ) ) );

  ulong scratch_footprint = stem_scratch_footprint( 1UL, 1UL, 1UL );
  void * scratch = fd_alloca( FD_STEM_SCRATCH_ALIGN, scratch_footprint );

  stem_run1( 1UL, in_mcache, in_fseq,
             1UL, out_mcache,
             1UL, cons_out, cons_fseq, cons_slow,
             1UL, 128L*3000L,
             rng, scratch, ctx );

  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  (void)privileged_init;
  (void)unprivileged_init;
  (void)populate_allowed_seccomp;
  (void)populate_allowed_fds;

  if( FD_UNLIKELY( fd_tile_cnt()<2UL ) ) FD_LOG_ERR(( "this test requires at least 2 tiles" ));

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"                 );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                        );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx(cpu_idx) );
  long         duration  = fd_env_strip_cmdline_long ( &argc, &argv, "--duration", NULL, (long)10e9                 );

  FD_LOG_NOTICE(( "Creating workspace (--page-sz %s --page-cnt %lu --numa-idx %lu)", _page_sz, page_cnt, numa_idx ));

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  ulong depth = 128UL;

  ulong req_data_sz  = fd_dcache_req_data_sz( 32UL, depth, 1UL, 1 );
  ulong resp_data_sz = fd_dcache_req_data_sz( 64UL, depth, 1UL, 1 );

  fd_frag_meta_t * req_mcache  = fd_mcache_join( fd_mcache_new( fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( depth, 0UL ), 1UL ), depth, 0UL, 0UL ) );
  uchar *          req_dcache  = fd_dcache_join( fd_dcache_new( fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( req_data_sz, 0UL ), 1UL ), req_data_sz, 0UL ) );
  ulong *          req_fseq   = fd_fseq_join  ( fd_fseq_new  ( fd_wksp_alloc_laddr( wksp, fd_fseq_align(),   fd_fseq_footprint(), 1UL ), 0UL ) );

  fd_frag_meta_t * resp_mcache = fd_mcache_join( fd_mcache_new( fd_wksp_alloc_laddr( wksp, fd_mcache_align(), fd_mcache_footprint( depth, 0UL ), 1UL ), depth, 0UL, 0UL ) );
  uchar *          resp_dcache = fd_dcache_join( fd_dcache_new( fd_wksp_alloc_laddr( wksp, fd_dcache_align(), fd_dcache_footprint( resp_data_sz, 0UL ), 1UL ), resp_data_sz, 0UL ) );
  ulong *          resp_fseq  = fd_fseq_join  ( fd_fseq_new  ( fd_wksp_alloc_laddr( wksp, fd_fseq_align(),   fd_fseq_footprint(), 1UL ), 0UL ) );

  FD_TEST( req_mcache && req_dcache && req_fseq && resp_mcache && resp_dcache && resp_fseq );

  fd_keyswitch_t * keyswitch = fd_keyswitch_join( fd_keyswitch_new( fd_wksp_alloc_laddr( wksp, fd_keyswitch_align(), fd_keyswitch_footprint(), 1UL ), FD_KEYSWITCH_STATE_LOCKED ) );
  FD_TEST( keyswitch );

  ulong * metrics = fd_wksp_alloc_laddr( wksp, FD_METRICS_ALIGN, FD_METRICS_FOOTPRINT( 1UL ), 1UL );
  FD_TEST( metrics );
  fd_metrics_new( metrics, 1UL );

  bench_sign_cfg_t cfg[1];
  cfg->req_mcache  = req_mcache;
  cfg->req_dcache  = req_dcache;
  cfg->req_fseq    = req_fseq;
  cfg->resp_mcache = resp_mcache;
  cfg->resp_dcache = resp_dcache;
  cfg->resp_fseq   = resp_fseq;
  cfg->keyswitch   = keyswitch;
  cfg->metrics     = metrics;
  cfg->wksp        = wksp;

  /* Generate a random ed25519 keypair and write it as a Solana JSON
     key file to a temp file so fd_keyload_load can read it. */

  uchar private_key[32];
  uchar public_key[32];

  fd_rng_t rng[1];
  FD_TEST( fd_rng_join( fd_rng_new( rng, 42U, 0UL ) ) );
  for( ulong i=0UL; i<32UL; i++ ) private_key[i] = fd_rng_uchar( rng );

  fd_sha512_t sha512[1];
  FD_TEST( fd_sha512_join( fd_sha512_new( sha512 ) ) );
  fd_ed25519_public_from_private( public_key, private_key, sha512 );

  char key_path[] = "/tmp/bench_sign_tile_XXXXXX";
  int key_fd = mkstemp( key_path );
  FD_TEST( key_fd>=0 );

  /* Write the 64-byte keypair (private||public) as a JSON array */
  uchar keypair[64];
  memcpy( keypair,      private_key, 32UL );
  memcpy( keypair+32UL, public_key,  32UL );

  char json_buf[512];
  int off = 0;
  json_buf[off++] = '[';
  for( ulong i=0UL; i<64UL; i++ ) {
    if( i ) json_buf[off++] = ',';
    off += sprintf( json_buf+off, "%u", (uint)keypair[i] );
  }
  json_buf[off++] = ']';

  FD_TEST( write( key_fd, json_buf, (ulong)off )==off );
  FD_TEST( !close( key_fd ) );

  cfg->key_path = key_path;

  /* Launch sign tile on tile index 1 */

  FD_TEST( fd_tile_exec_new( 1UL, sign_tile_main, 0, (char **)fd_type_pun( cfg ) ) );

  /* Pipelined client loop on tile 0 */

  FD_LOG_NOTICE(( "Running benchmark (--duration %li ns)", duration ));

  ulong req_chunk0 = fd_dcache_compact_chunk0( wksp, req_dcache );
  ulong req_wmark  = fd_dcache_compact_wmark ( wksp, req_dcache, 32UL );
  ulong req_chunk  = req_chunk0;
  ulong req_seq    = 0UL;

  ulong resp_chunk0 = fd_dcache_compact_chunk0( wksp, resp_dcache );
  ulong resp_wmark  = fd_dcache_compact_wmark ( wksp, resp_dcache, 64UL );
  ulong resp_seq    = 0UL;

  ulong sig_cnt   = 0UL;
  ulong in_flight = 0UL;
  long  t0        = 0L;
  long  deadline  = LONG_MAX;

  for(;;) {
    int done = fd_log_wallclock()>=deadline;

    /* Harvest any available responses (non-blocking) */

    for(;;) {
      fd_frag_meta_t const * resp_line = resp_mcache + fd_mcache_line_idx( resp_seq, depth );
      ulong seq_found = fd_frag_meta_seq_query( resp_line );
      long  seq_diff  = fd_seq_diff( seq_found, resp_seq );
      if( FD_LIKELY( seq_diff<0L ) ) break;

      if( FD_UNLIKELY( seq_diff>0L ) ) FD_LOG_ERR(( "response overrun" ));

      ulong chunk = resp_line->chunk;
      if( FD_UNLIKELY( chunk<resp_chunk0 || chunk>resp_wmark ) ) FD_LOG_ERR(( "bad response chunk" ));

      seq_found = fd_frag_meta_seq_query( resp_line );
      if( FD_UNLIKELY( fd_seq_ne( seq_found, resp_seq ) ) ) FD_LOG_ERR(( "response torn" ));

      resp_seq = fd_seq_inc( resp_seq, 1UL );
      fd_fseq_update( resp_fseq, resp_seq );
      in_flight--;
      sig_cnt++;

      if( FD_UNLIKELY( !t0 ) ) {
        t0       = fd_log_wallclock();
        deadline = t0 + duration;
        sig_cnt  = 0UL;
      }
    }

    if( FD_UNLIKELY( done ) ) break;

    /* Submit requests up to depth in-flight */

    while( in_flight<depth ) {
      uchar * dst = fd_chunk_to_laddr( wksp, req_chunk );
      memset( dst, 0xAB, 32UL );

      ulong sig = (ulong)(uint)FD_KEYGUARD_SIGN_TYPE_ED25519;
      fd_mcache_publish( req_mcache, depth, req_seq, sig, req_chunk, 32UL, 0UL, 0UL, 0UL );

      req_seq   = fd_seq_inc( req_seq, 1UL );
      req_chunk = fd_dcache_compact_next( req_chunk, 32UL, req_chunk0, req_wmark );
      in_flight++;
    }
  }

  /* Drain remaining in-flight requests */

  while( in_flight ) {
    fd_frag_meta_t const * resp_line = resp_mcache + fd_mcache_line_idx( resp_seq, depth );
    ulong seq_found = fd_frag_meta_seq_query( resp_line );
    long  seq_diff  = fd_seq_diff( seq_found, resp_seq );
    if( FD_LIKELY( seq_diff<0L ) ) continue;

    if( FD_UNLIKELY( seq_diff>0L ) ) FD_LOG_ERR(( "response overrun (drain)" ));

    seq_found = fd_frag_meta_seq_query( resp_line );
    if( FD_UNLIKELY( fd_seq_ne( seq_found, resp_seq ) ) ) FD_LOG_ERR(( "response torn (drain)" ));

    resp_seq = fd_seq_inc( resp_seq, 1UL );
    fd_fseq_update( resp_fseq, resp_seq );
    in_flight--;
    sig_cnt++;
  }

  long t1 = fd_log_wallclock();

  FD_COMPILER_MFENCE();
  stop = 1;
  FD_COMPILER_MFENCE();

  int ret;
  FD_TEST( !fd_tile_exec_delete( fd_tile_exec( 1UL ), &ret ) );
  FD_TEST( !ret );

  double elapsed_s  = (double)(t1 - t0) / 1e9;
  double sigs_per_s = (double)sig_cnt / elapsed_s;

  FD_LOG_NOTICE(( "%lu signatures in %.3f s (%.0f sig/s, %.3f us/sig)",
                  sig_cnt, elapsed_s, sigs_per_s, 1e6/sigs_per_s ));

  unlink( key_path );
  fd_wksp_delete_anonymous( wksp );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: not hosted or no alloca" ));
  fd_halt();
  return 0;
}

#endif
